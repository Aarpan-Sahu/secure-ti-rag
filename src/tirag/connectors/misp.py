"""MISP connector (REST API: ``POST /events/restSearch``).

Each MISP event becomes up to three kinds of documents:

* an ``event`` document (narrative: info, threat level, tags, galaxy context, event reports),
* an ``indicator`` document (the attribute / object IOCs, one per line),
* ``threat_actor`` / ``malware`` documents from the galaxy clusters attached to the event.

Only *published* events are requested, TLP is derived from ``tlp:*`` tags (most restrictive
wins; missing tag falls back to the configured default), and an optional allow-list of creator
organisations limits what can enter the index (RAG-poisoning control).
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx

from tirag.connectors.base import ConnectorError, request_with_retry, validate_base_url
from tirag.models import TLP, DocType, ThreatDoc

log = logging.getLogger(__name__)

THREAT_LEVEL = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}
ANALYSIS = {"0": "Initial", "1": "Ongoing", "2": "Completed"}

_ACTOR_GALAXIES = ("threat-actor", "intrusion-set", "tool-actor")
_MALWARE_GALAXIES = ("malware", "malpedia", "ransomware", "tool", "stealer", "banker", "rat")

_SIMPLE_TYPES = {
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "link": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email-src": "email",
    "email-dst": "email",
    "email": "email",
    "vulnerability": "cve",
}


def _ts(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _ip_label(value: str) -> str:
    try:
        return (
            "ipv6"
            if isinstance(ipaddress.ip_address(value.strip()), ipaddress.IPv6Address)
            else "ipv4"
        )
    except ValueError:
        return "ip"


def format_attribute(attr: dict[str, Any]) -> str | None:
    """Render one MISP attribute as a single, self-describing line (or None to skip)."""
    a_type = str(attr.get("type", "")).strip()
    value = str(attr.get("value", "")).strip()
    if not a_type or not value:
        return None
    category = attr.get("category") or ""
    comment = str(attr.get("comment") or "").strip()
    flags = "IDS" if str(attr.get("to_ids")).lower() in ("1", "true") else "context"

    if "|" in a_type and "|" in value:
        left_t, right_t = a_type.split("|", 1)
        left_v, right_v = value.split("|", 1)
        if right_t in ("md5", "sha1", "sha256"):
            label, shown = right_t, f"{right_v} (filename: {left_v})"
        elif left_t.startswith("ip-"):
            label, shown = _ip_label(left_v), f"{left_v} (port {right_v})"
        elif right_t.startswith("ip-"):
            label, shown = _ip_label(right_v), f"{right_v} ({left_t}: {left_v})"
        else:
            label, shown = a_type, value
    elif a_type.startswith("ip-"):
        label, shown = _ip_label(value), value
    else:
        label, shown = _SIMPLE_TYPES.get(a_type, a_type), value

    suffix = f" - {comment}" if comment else ""
    return f"- {label}: {shown} [{category}; {flags}]{suffix}"


def _galaxy_kind(galaxy_type: str) -> DocType | None:
    gt = galaxy_type.lower()
    if any(k in gt for k in _ACTOR_GALAXIES):
        return DocType.THREAT_ACTOR
    if any(k in gt for k in _MALWARE_GALAXIES):
        return DocType.MALWARE
    return None


class MispConnector:
    name = "misp"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        client: httpx.Client | None = None,
        verify_tls: bool = True,
        trusted_orgs: set[str] | None = None,
        page_size: int = 50,
        default_tlp: TLP = TLP.AMBER,
        allow_http: bool = False,
        max_pages: int = 1000,
    ) -> None:
        self.base_url = validate_base_url(base_url, allow_http)
        self._api_key = api_key
        self._client = client or httpx.Client(
            timeout=30.0, verify=verify_tls, follow_redirects=False
        )
        self._trusted = {o.lower() for o in (trusted_orgs or set())}
        self._page_size = page_size
        self._default_tlp = default_tlp
        self._max_pages = max_pages
        self.skipped = 0

    # ------------------------------------------------------------------------------------
    def _search(self, since: datetime, page: int) -> list[dict[str, Any]]:
        body = {
            "returnFormat": "json",
            "limit": self._page_size,
            "page": page,
            "timestamp": int(since.timestamp()),
            "published": True,
            "includeEventTags": True,
            "includeContext": True,
        }
        response = request_with_retry(
            self._client,
            "POST",
            f"{self.base_url}/events/restSearch",
            json=body,
            headers={
                "Authorization": self._api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        if response.status_code in (401, 403):
            raise ConnectorError(f"MISP rejected the API key (HTTP {response.status_code})")
        if response.status_code != 200:
            raise ConnectorError(f"MISP returned HTTP {response.status_code}")
        try:
            payload = response.json()
            events = payload["response"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ConnectorError("unexpected MISP response shape") from exc
        if not isinstance(events, list):
            raise ConnectorError("unexpected MISP response shape")
        return events

    def fetch(self, since: datetime) -> Iterator[ThreatDoc]:
        self.skipped = 0
        clusters: dict[str, ThreatDoc] = {}
        for page in range(1, self._max_pages + 1):
            events = self._search(since, page)
            for wrapper in events:
                event = wrapper.get("Event") if isinstance(wrapper, dict) else None
                if not isinstance(event, dict):
                    continue
                yield from self._event_docs(event, clusters)
            if len(events) < self._page_size:
                break
        yield from clusters.values()

    # ------------------------------------------------------------------------------------
    def _event_tlp(self, tags: list[str]) -> TLP:
        labels = [TLP.parse(t) for t in tags if t.lower().startswith("tlp:")]
        return TLP.most_restrictive(labels, self._default_tlp)

    def _event_docs(
        self, event: dict[str, Any], clusters: dict[str, ThreatDoc]
    ) -> Iterator[ThreatDoc]:
        event_id = str(event.get("uuid") or event.get("id") or "")
        if not event_id:
            return
        org = str((event.get("Orgc") or {}).get("name") or "unknown")
        if self._trusted and org.lower() not in self._trusted:
            self.skipped += 1
            log.info(
                "skipping MISP event from untrusted org", extra={"event_id": event_id, "org": org}
            )
            return

        tags = [str(t.get("name", "")) for t in event.get("Tag", []) if isinstance(t, dict)]
        tlp = self._event_tlp(tags)
        info = str(event.get("info") or f"MISP event {event_id}")
        modified = _ts(event.get("timestamp"))
        url = f"{self.base_url}/events/view/{event.get('id', event_id)}"
        labels = [t for t in tags if not t.lower().startswith("tlp:")][:20]

        galaxy_lines: list[str] = []
        for galaxy in event.get("Galaxy", []) or []:
            g_type = str(galaxy.get("type") or galaxy.get("name") or "galaxy")
            for cluster in galaxy.get("GalaxyCluster", []) or []:
                value = str(cluster.get("value") or "").strip()
                if not value:
                    continue
                galaxy_lines.append(f"{galaxy.get('name', g_type)}: {value}")
                kind = _galaxy_kind(g_type)
                if kind is not None:
                    self._merge_cluster(clusters, cluster, kind, tlp, modified, url, org)

        lines = [
            f"MISP event {event.get('id', event_id)} reported by {org}.",
            f"Date: {event.get('date', 'unknown')}. "
            f"Threat level: {THREAT_LEVEL.get(str(event.get('threat_level_id')), 'Undefined')}. "
            f"Analysis: {ANALYSIS.get(str(event.get('analysis')), 'Initial')}.",
        ]
        if labels:
            lines.append("Tags: " + ", ".join(labels))
        if galaxy_lines:
            lines.append("Context: " + "; ".join(galaxy_lines))
        for report in event.get("EventReport", []) or []:
            name = str(report.get("name") or "report")
            content = str(report.get("content") or "").strip()
            if content:
                lines.append(f"\n## {name}\n{content}")

        common = {
            "source": self.name,
            "tlp": tlp,
            "created": _ts(event.get("publish_timestamp")),
            "modified": modified,
        }
        yield ThreatDoc(
            source_id=event_id,
            doc_type=DocType.EVENT,
            title=info,
            text="\n".join(lines),
            url=url,
            labels=labels,
            extra={"org": org, "misp_event_id": str(event.get("id", ""))},
            **common,  # type: ignore[arg-type]
        )

        attr_lines: list[str] = []
        attributes = list(event.get("Attribute", []) or [])
        for obj in event.get("Object", []) or []:
            for attr in obj.get("Attribute", []) or []:
                merged = dict(attr)
                merged.setdefault("comment", obj.get("comment") or obj.get("name") or "")
                attributes.append(merged)
        for attr in attributes:
            line = format_attribute(attr)
            if line:
                attr_lines.append(line)
        if attr_lines:
            yield ThreatDoc(
                source_id=f"{event_id}#iocs",
                doc_type=DocType.INDICATOR,
                title=f"Indicators of compromise for MISP event: {info}",
                text="\n".join(attr_lines),
                url=url,
                labels=labels,
                extra={"org": org, "misp_event_id": str(event.get("id", ""))},
                **common,  # type: ignore[arg-type]
            )

    def _merge_cluster(
        self,
        clusters: dict[str, ThreatDoc],
        cluster: dict[str, Any],
        kind: DocType,
        tlp: TLP,
        modified: datetime | None,
        url: str,
        org: str,
    ) -> None:
        value = str(cluster.get("value", "")).strip()
        key = str(cluster.get("uuid") or f"{kind.value}-{value.lower()}")
        meta = cluster.get("meta") or {}
        parts = [str(cluster.get("description") or "").strip()]
        for field_name in (
            "synonyms",
            "country",
            "cfr-suspected-victims",
            "cfr-target-category",
            "refs",
        ):
            raw = meta.get(field_name)
            if raw:
                items = raw if isinstance(raw, list) else [raw]
                parts.append(
                    f"{field_name.replace('-', ' ').capitalize()}: " + ", ".join(map(str, items))
                )
        text = "\n".join(p for p in parts if p)
        existing = clusters.get(key)
        if existing is not None:
            # The same public cluster can appear in events with different TLP: keep the strictest.
            if tlp.rank > existing.tlp.rank:
                existing.tlp = tlp
            return
        clusters[key] = ThreatDoc(
            source=self.name,
            source_id=key,
            doc_type=kind,
            title=value,
            text=text or f"{value} (no description in MISP galaxy cluster)",
            tlp=tlp,
            url=url,
            modified=modified,
            labels=[str(cluster.get("tag_name", ""))] if cluster.get("tag_name") else [],
            extra={"org": org},
        )
