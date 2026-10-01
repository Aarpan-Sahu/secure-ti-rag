"""OpenCTI connector (GraphQL API at ``/graphql``, bearer-token auth).

Pulls threat actors, intrusion sets, malware, campaigns, reports and indicators that were
updated since the last sync, using cursor pagination. TLP comes from the object's marking
definitions (``TLP:AMBER`` etc.); the most restrictive marking wins.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from tirag.connectors.base import ConnectorError, request_with_retry, validate_base_url
from tirag.models import TLP, DocType, ThreatDoc

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Entity:
    root: str
    doc_type: DocType
    fields: str  # extra GraphQL selection beyond the common fields


_COMMON = (
    "id standard_id name description created modified "
    "objectLabel { value } objectMarking { definition definition_type } createdBy { name }"
)

ENTITIES: tuple[_Entity, ...] = (
    _Entity(
        "threatActorsGroup",
        DocType.THREAT_ACTOR,
        "aliases first_seen last_seen threat_actor_types goals sophistication resource_level "
        "primary_motivation secondary_motivations roles",
    ),
    _Entity(
        "intrusionSets",
        DocType.INTRUSION_SET,
        "aliases first_seen last_seen goals resource_level primary_motivation secondary_motivations",
    ),
    _Entity(
        "malwares",
        DocType.MALWARE,
        "aliases malware_types is_family first_seen last_seen architecture_execution_envs "
        "implementation_languages capabilities",
    ),
    _Entity("campaigns", DocType.CAMPAIGN, "aliases first_seen last_seen objective"),
    _Entity("reports", DocType.REPORT, "published report_types content"),
    _Entity(
        "indicators",
        DocType.INDICATOR,
        "pattern pattern_type valid_from valid_until x_opencti_score revoked indicator_types",
    ),
)

QUERY_TEMPLATE = """
query TiragList($first: Int!, $after: ID, $filters: FilterGroup) {
  %(root)s(first: $first, after: $after, filters: $filters) {
    edges { node { %(common)s %(fields)s } }
    pageInfo { endCursor hasNextPage }
  }
}
"""

_RE_STIX_COMPARISON = re.compile(
    r"\[?\s*(?P<obj>[a-z0-9-]+):(?P<path>[A-Za-z0-9_.'\"-]+)\s*=\s*'(?P<value>(?:[^'\\]|\\.)*)'"
)

_STIX_TYPE = {
    "ipv4-addr": "ipv4",
    "ipv6-addr": "ipv6",
    "domain-name": "domain",
    "url": "url",
    "email-addr": "email",
}

_HASH_PATH = {"'md5'": "md5", "'sha-1'": "sha1", "'sha-256'": "sha256"}

_MAX_PAGES = 2000


def parse_stix_pattern(pattern: str) -> list[tuple[str, str]]:
    """Return ``[(label, value)]`` observables from a STIX 2.1 pattern string."""
    result: list[tuple[str, str]] = []
    for m in _RE_STIX_COMPARISON.finditer(pattern or ""):
        obj, path, value = m.group("obj"), m.group("path"), m.group("value").replace("\\'", "'")
        if obj in _STIX_TYPE:
            result.append((_STIX_TYPE[obj], value))
        elif obj == "file" and path.lower().startswith("hashes."):
            key = path.split(".", 1)[1].lower().replace('"', "'")
            result.append((_HASH_PATH.get(key, key.strip("'")), value))
        elif obj == "file" and path.lower() == "name":
            result.append(("filename", value))
        else:
            result.append((f"{obj}:{path}", value))
    return result


def _iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _join(label: str, value: Any) -> str | None:
    if value in (None, "", [], False):
        return None
    if isinstance(value, list):
        value = ", ".join(map(str, value))
    return f"{label}: {value}"


class OpenCTIConnector:
    name = "opencti"

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        client: httpx.Client | None = None,
        verify_tls: bool = True,
        page_size: int = 50,
        default_tlp: TLP = TLP.AMBER,
        allow_http: bool = False,
    ) -> None:
        self.base_url = validate_base_url(base_url, allow_http)
        self._token = token
        self._client = client or httpx.Client(
            timeout=30.0, verify=verify_tls, follow_redirects=False
        )
        self._page_size = page_size
        self._default_tlp = default_tlp
        self.skipped = 0

    # ------------------------------------------------------------------------------------
    def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        response = request_with_retry(
            self._client,
            "POST",
            f"{self.base_url}/graphql",
            json={"query": query, "variables": variables},
            headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
        )
        if response.status_code in (401, 403):
            raise ConnectorError(f"OpenCTI rejected the token (HTTP {response.status_code})")
        if response.status_code != 200:
            raise ConnectorError(f"OpenCTI returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise ConnectorError("OpenCTI returned non-JSON") from exc
        if payload.get("errors"):
            message = str(payload["errors"][0].get("message", "unknown error"))[:200]
            raise ConnectorError(f"OpenCTI GraphQL error: {message}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ConnectorError("unexpected OpenCTI response shape")
        return data

    def fetch(self, since: datetime) -> Iterator[ThreatDoc]:
        self.skipped = 0
        filters = {
            "mode": "and",
            "filters": [
                {
                    "key": "updated_at",
                    "values": [since.astimezone(UTC).isoformat()],
                    "operator": "gt",
                }
            ],
            "filterGroups": [],
        }
        for entity in ENTITIES:
            query = QUERY_TEMPLATE % {
                "root": entity.root,
                "common": _COMMON,
                "fields": entity.fields,
            }
            after: str | None = None
            for _ in range(_MAX_PAGES):
                data = self._graphql(
                    query, {"first": self._page_size, "after": after, "filters": filters}
                )
                connection = data.get(entity.root) or {}
                for edge in connection.get("edges", []) or []:
                    node = edge.get("node") if isinstance(edge, dict) else None
                    if isinstance(node, dict):
                        doc = self._to_doc(entity, node)
                        if doc is not None:
                            yield doc
                page_info = connection.get("pageInfo") or {}
                if not page_info.get("hasNextPage") or not page_info.get("endCursor"):
                    break
                after = page_info["endCursor"]

    # ------------------------------------------------------------------------------------
    def _tlp(self, node: dict[str, Any]) -> TLP:
        labels = [
            TLP.parse(m.get("definition"))
            for m in node.get("objectMarking") or []
            if str(m.get("definition", "")).upper().startswith("TLP:")
        ]
        return TLP.most_restrictive(labels, self._default_tlp)

    def _to_doc(self, entity: _Entity, node: dict[str, Any]) -> ThreatDoc | None:
        source_id = str(node.get("standard_id") or node.get("id") or "")
        name = str(node.get("name") or "").strip()
        if not source_id or not name:
            return None
        labels = [
            str(label.get("value")) for label in node.get("objectLabel") or [] if label.get("value")
        ]
        author = (node.get("createdBy") or {}).get("name")
        header = [d for d in (_join("Aliases", node.get("aliases")), _join("Author", author)) if d]
        description = str(node.get("description") or "").strip()

        if entity.doc_type == DocType.INDICATOR:
            if node.get("revoked"):
                self.skipped += 1
                return None
            observables = parse_stix_pattern(str(node.get("pattern") or ""))
            lines = [f"- {label}: {value}" for label, value in observables] or [
                f"- pattern: {node.get('pattern', '')}"
            ]
            meta = [
                d
                for d in (
                    _join("Indicator types", node.get("indicator_types")),
                    _join("Score", node.get("x_opencti_score")),
                    _join("Valid from", node.get("valid_from")),
                    _join("Valid until", node.get("valid_until")),
                )
                if d
            ]
            body = "\n".join([*header, *meta, description, *lines])
        else:
            attrs = [
                d
                for d in (
                    _join(
                        "Types",
                        node.get("threat_actor_types")
                        or node.get("malware_types")
                        or node.get("report_types"),
                    ),
                    _join("Sophistication", node.get("sophistication")),
                    _join("Resource level", node.get("resource_level")),
                    _join("Primary motivation", node.get("primary_motivation")),
                    _join("Secondary motivations", node.get("secondary_motivations")),
                    _join("Goals", node.get("goals") or node.get("objective")),
                    _join("Roles", node.get("roles")),
                    _join("Capabilities", node.get("capabilities")),
                    _join("Implementation languages", node.get("implementation_languages")),
                    _join("Execution environments", node.get("architecture_execution_envs")),
                    _join("First seen", node.get("first_seen")),
                    _join("Last seen", node.get("last_seen")),
                    _join("Published", node.get("published")),
                )
                if d
            ]
            content = (
                str(node.get("content") or "").strip() if entity.doc_type == DocType.REPORT else ""
            )
            body = "\n".join([*header, *attrs, description, content]).strip()

        return ThreatDoc(
            source=self.name,
            source_id=source_id,
            doc_type=entity.doc_type,
            title=name,
            text=body,
            tlp=self._tlp(node),
            url=f"{self.base_url}/dashboard/id/{node.get('id', source_id)}",
            created=_iso(node.get("created")),
            modified=_iso(node.get("modified")),
            labels=labels[:20],
            extra={"author": author or "unknown"},
        )
