"""The HTTP mock server speaks the same protocol the connectors expect (real HTTP semantics via ASGI)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tools.mock_feeds_server import app

from tirag.connectors.misp import MispConnector
from tirag.connectors.mock_feeds import EPOCH, MockFeeds
from tirag.connectors.opencti import OpenCTIConnector

feeds = MockFeeds()


def test_connectors_work_against_the_http_mock_server() -> None:
    client = TestClient(app, base_url="http://mock.invalid")  # a TestClient *is* an httpx.Client
    misp_docs = list(
        MispConnector("http://mock.invalid", feeds.misp_key, client=client, allow_http=True).fetch(
            EPOCH
        )
    )
    octi_docs = list(
        OpenCTIConnector(
            "http://mock.invalid", feeds.opencti_token, client=client, allow_http=True
        ).fetch(EPOCH)
    )
    assert len(misp_docs) == 15 and len(octi_docs) == 16


def test_mock_server_enforces_credentials() -> None:
    client = TestClient(app)
    assert (
        client.post("/events/restSearch", json={}, headers={"Authorization": "wrong"}).status_code
        == 403
    )
    assert client.post("/graphql", json={"query": "{}"}).status_code == 401
