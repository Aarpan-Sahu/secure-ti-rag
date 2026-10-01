"""Mock MISP / OpenCTI servers backed by the synthetic fixtures.

The same request handlers serve three purposes:

* an in-process ``httpx.MockTransport`` used by unit/integration tests and the ``fixtures``
  ingest source (so the *real* connector code is exercised, not a shortcut),
* the demo server in ``tools/mock_feeds_server.py`` used by docker-compose,
* a contract check of the request/response shapes the connectors depend on.

The shapes follow the public MISP ``/events/restSearch`` and OpenCTI GraphQL list-query
conventions. They are NOT a substitute for testing against a live MISP/OpenCTI instance.
"""

from __future__ import annotations

import base64
import json
import re
from datetime import UTC, datetime
from importlib import resources
from typing import Any

import httpx

from tirag.config import Settings
from tirag.connectors.misp import MispConnector
from tirag.connectors.opencti import ENTITIES, OpenCTIConnector

_ROOT_RE = re.compile(r"\b(" + "|".join(e.root for e in ENTITIES) + r")\s*\(")
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _load(name: str) -> Any:
    return json.loads((resources.files("tirag") / "fixtures" / name).read_text(encoding="utf-8"))


class MockFeeds:
    def __init__(self, misp_key: str = "mock-misp-key", opencti_token: str = "mock-opencti-token") -> None:
        self.misp_key = misp_key
        self.opencti_token = opencti_token
        self._misp = _load("misp_restsearch.json")["response"]
        self._octi = _load("opencti_graphql.json")
        self.requests: list[tuple[str, str]] = []  # (path, auth) - lets tests assert on calls

    # --- MISP ------------------------------------------------------------------------------
    def misp_search(self, headers: httpx.Headers, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if headers.get("Authorization") != self.misp_key:
            return 403, {"name": "Authentication failed"}
        since = int(body.get("timestamp", 0))
        limit = max(1, min(int(body.get("limit", 50)), 500))
        page = max(1, int(body.get("page", 1)))
        events = [
            e
            for e in self._misp
            if int(e["Event"]["timestamp"]) >= since
            and (not body.get("published") or e["Event"].get("published"))
        ]
        return 200, {"response": events[(page - 1) * limit : page * limit]}

    # --- OpenCTI ---------------------------------------------------------------------------
    def opencti_graphql(self, headers: httpx.Headers, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if headers.get("Authorization") != f"Bearer {self.opencti_token}":
            return 401, {"errors": [{"message": "You must be logged in"}]}
        match = _ROOT_RE.search(str(body.get("query", "")))
        if not match:
            return 200, {"errors": [{"message": "Cannot query unknown field"}]}
        root = match.group(1)
        variables = body.get("variables") or {}
        first = max(1, min(int(variables.get("first", 50)), 500))
        offset = int(base64.b64decode(variables["after"]).decode()) if variables.get("after") else 0
        since: datetime | None = None
        for flt in (variables.get("filters") or {}).get("filters", []):
            if flt.get("key") == "updated_at" and flt.get("operator") == "gt":
                since = datetime.fromisoformat(flt["values"][0].replace("Z", "+00:00"))
        nodes = [
            n
            for n in self._octi.get(root, [])
            if since is None or datetime.fromisoformat(n["modified"].replace("Z", "+00:00")) > since
        ]
        window = nodes[offset : offset + first]
        has_next = offset + first < len(nodes)
        end_cursor = base64.b64encode(str(offset + first).encode()).decode() if has_next else None
        return 200, {
            "data": {
                root: {
                    "edges": [{"node": n} for n in window],
                    "pageInfo": {"endCursor": end_cursor, "hasNextPage": has_next},
                }
            }
        }

    # --- transport -------------------------------------------------------------------------
    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.url.path, request.headers.get("Authorization", "")))
        body = json.loads(request.content or b"{}")
        if request.method == "POST" and request.url.path == "/events/restSearch":
            status, payload = self.misp_search(request.headers, body)
        elif request.method == "POST" and request.url.path == "/graphql":
            status, payload = self.opencti_graphql(request.headers, body)
        else:
            status, payload = 404, {"message": "not found"}
        return httpx.Response(status, json=payload)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def fixture_connectors(settings: Settings, feeds: MockFeeds | None = None) -> list[Any]:
    """Real connectors wired to the in-process mock feeds (``--source fixtures``)."""
    feeds = feeds or MockFeeds()
    client = feeds.client()
    connectors: list[Any] = [
        MispConnector(
            "http://mock-misp.invalid",
            feeds.misp_key,
            client=client,
            page_size=settings.misp_page_size,
            default_tlp=settings.default_tlp_label,
            trusted_orgs=settings.misp_trusted_org_set,
            allow_http=True,
        ),
        OpenCTIConnector(
            "http://mock-opencti.invalid",
            feeds.opencti_token,
            client=client,
            page_size=settings.opencti_page_size,
            default_tlp=settings.default_tlp_label,
            allow_http=True,
        ),
    ]
    for connector in connectors:
        connector.full_history = True  # fixtures are static: ignore the sync window
    return connectors
