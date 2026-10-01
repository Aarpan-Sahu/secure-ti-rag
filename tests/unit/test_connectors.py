from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from tests.conftest import make_settings
from tirag.connectors import ConnectorError, build_connectors
from tirag.connectors.base import request_with_retry, validate_base_url
from tirag.connectors.misp import MispConnector, format_attribute
from tirag.connectors.mock_feeds import EPOCH, MockFeeds
from tirag.connectors.opencti import OpenCTIConnector, parse_stix_pattern
from tirag.models import TLP, DocType


@pytest.fixture
def feeds() -> MockFeeds:
    return MockFeeds()


def misp(feeds: MockFeeds, **kw) -> MispConnector:
    return MispConnector(
        "http://mock-misp.invalid", feeds.misp_key, client=feeds.client(), allow_http=True, **kw
    )


def octi(feeds: MockFeeds, **kw) -> OpenCTIConnector:
    return OpenCTIConnector(
        "http://mock-opencti.invalid",
        feeds.opencti_token,
        client=feeds.client(),
        allow_http=True,
        **kw,
    )


# ----------------------------------------------------------------------------- MISP


def test_misp_produces_event_indicator_and_galaxy_documents(feeds: MockFeeds) -> None:
    docs = list(misp(feeds).fetch(EPOCH))
    kinds = {d.doc_type for d in docs}
    assert {DocType.EVENT, DocType.INDICATOR, DocType.THREAT_ACTOR, DocType.MALWARE} <= kinds
    actors = {d.title for d in docs if d.doc_type == DocType.THREAT_ACTOR}
    assert {"STORMVEIL", "COPPER HERON", "NIGHT KESTREL"} <= actors


def test_misp_tlp_is_taken_from_tags_with_fail_closed_default(feeds: MockFeeds) -> None:
    by_id = {d.source_id: d for d in misp(feeds).fetch(EPOCH)}
    tlps = {d.title: d.tlp for d in by_id.values() if d.doc_type == DocType.EVENT}
    assert tlps["STORMVEIL phishing campaign against regional hospitals (ISO lure)"] is TLP.AMBER
    assert tlps["NIGHT KESTREL abuse of leaked cloud access keys"] is TLP.CLEAR  # tlp:white
    assert any(t is TLP.RED for t in tlps.values())
    # an event with no TLP tag falls back to the configured default
    conn = misp(feeds, default_tlp=TLP.RED)
    assert conn._event_tlp(["sector:finance"]) is TLP.RED


def test_misp_formats_composite_and_ip_attributes() -> None:
    assert (
        format_attribute(
            {
                "type": "ip-dst|port",
                "value": "198.51.100.23|443",
                "category": "Network activity",
                "to_ids": True,
                "comment": "c2",
            }
        )
        == "- ipv4: 198.51.100.23 (port 443) [Network activity; IDS] - c2"
    )
    line = format_attribute(
        {
            "type": "filename|sha256",
            "value": "a.iso|" + "a" * 64,
            "category": "Payload delivery",
            "to_ids": False,
        }
    )
    assert (
        line is not None and line.startswith("- sha256: " + "a" * 64) and "filename: a.iso" in line
    )
    assert format_attribute(
        {"type": "ip-src", "value": "2001:db8::1", "category": "x", "to_ids": 1}
    ).startswith("- ipv6:")
    assert format_attribute(
        {"type": "vulnerability", "value": "CVE-2099-1", "category": "x"}
    ).startswith("- cve:")
    assert format_attribute({"type": "", "value": "x"}) is None


def test_misp_trusted_org_allow_list_skips_untrusted_events(feeds: MockFeeds) -> None:
    conn = misp(feeds, trusted_orgs={"ACME-CSIRT"})
    docs = list(conn.fetch(EPOCH))
    assert conn.skipped == 1  # the OpenShare-Community event
    assert all(d.extra.get("org", "ACME-CSIRT") == "ACME-CSIRT" for d in docs)
    assert not any("weekly-digest" in d.text for d in docs)


def test_misp_pagination_returns_everything_once(feeds: MockFeeds) -> None:
    small = {d.source_id for d in misp(feeds, page_size=2).fetch(EPOCH)}
    big = {d.source_id for d in misp(feeds, page_size=50).fetch(EPOCH)}
    assert small == big and len(big) > 5
    assert sum(1 for path, _ in feeds.requests if path == "/events/restSearch") >= 3


def test_misp_since_filters_events(feeds: MockFeeds) -> None:
    cutoff = datetime(2026, 9, 21, tzinfo=UTC)
    titles = {d.title for d in misp(feeds).fetch(cutoff) if d.doc_type == DocType.EVENT}
    assert not any("NetGate" in t for t in titles)
    assert any("Restricted source report" in t for t in titles)


def test_galaxy_cluster_keeps_the_most_restrictive_tlp_across_events(feeds: MockFeeds) -> None:
    conn = misp(feeds)
    clusters: dict = {}
    cluster = {"uuid": "c-1", "value": "ACTOR", "description": "d", "meta": {}}
    conn._merge_cluster(clusters, cluster, DocType.THREAT_ACTOR, TLP.GREEN, None, "u", "o")
    conn._merge_cluster(clusters, cluster, DocType.THREAT_ACTOR, TLP.RED, None, "u", "o")
    conn._merge_cluster(clusters, cluster, DocType.THREAT_ACTOR, TLP.CLEAR, None, "u", "o")
    assert clusters["c-1"].tlp is TLP.RED


def test_misp_bad_key_and_bad_shape_raise_connector_error() -> None:
    feeds = MockFeeds()
    bad = MispConnector("http://x.invalid", "wrong", client=feeds.client(), allow_http=True)
    with pytest.raises(ConnectorError, match="rejected"):
        list(bad.fetch(EPOCH))
    weird = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"nope": 1}))
    )
    with pytest.raises(ConnectorError, match="shape"):
        list(MispConnector("http://x.invalid", "k", client=weird, allow_http=True).fetch(EPOCH))


# ----------------------------------------------------------------------------- OpenCTI


def test_stix_pattern_parsing() -> None:
    assert parse_stix_pattern("[ipv4-addr:value = '198.51.100.23']") == [("ipv4", "198.51.100.23")]
    assert parse_stix_pattern("[domain-name:value = 'a.example.net']") == [
        ("domain", "a.example.net")
    ]
    assert parse_stix_pattern("[file:hashes.'SHA-256' = 'abc'] OR [file:hashes.MD5 = 'd']")[0] == (
        "sha256",
        "abc",
    )
    assert parse_stix_pattern("[url:value = 'http://x.example.org/a']") == [
        ("url", "http://x.example.org/a")
    ]
    assert parse_stix_pattern("[file:name = 'evil.exe']") == [("filename", "evil.exe")]
    assert parse_stix_pattern("garbage") == []


def test_opencti_fetches_all_entity_types_and_skips_revoked(feeds: MockFeeds) -> None:
    conn = octi(feeds)
    docs = list(conn.fetch(EPOCH))
    by_type: dict[DocType, int] = {}
    for d in docs:
        by_type[d.doc_type] = by_type.get(d.doc_type, 0) + 1
    assert by_type == {
        DocType.THREAT_ACTOR: 3,
        DocType.INTRUSION_SET: 1,
        DocType.MALWARE: 3,
        DocType.CAMPAIGN: 1,
        DocType.REPORT: 3,
        DocType.INDICATOR: 5,
    }
    assert conn.skipped == 1
    assert not any("203.0.113.99" in d.text for d in docs)


def test_opencti_tlp_markings_and_indicator_text(feeds: MockFeeds) -> None:
    docs = {d.title: d for d in octi(feeds).fetch(EPOCH)}
    assert docs["STORMVEIL"].tlp is TLP.AMBER
    assert docs["COPPER HERON telecom signalling targeting (restricted)"].tlp is TLP.AMBER_STRICT
    assert docs["Detecting cloud credential abuse by NIGHT KESTREL"].tlp is TLP.CLEAR
    assert "- ipv4: 198.51.100.23" in docs["STORMVEIL C2 198.51.100.23"].text


def test_opencti_cursor_pagination_and_since(feeds: MockFeeds) -> None:
    assert {d.source_id for d in octi(feeds, page_size=1).fetch(EPOCH)} == {
        d.source_id for d in octi(feeds).fetch(EPOCH)
    }
    recent = list(octi(feeds).fetch(datetime(2026, 9, 25, tzinfo=UTC)))
    assert {d.title for d in recent} == {
        "COPPER HERON telecom signalling targeting (restricted)",
        "Detecting cloud credential abuse by NIGHT KESTREL",
    }


def test_opencti_auth_and_graphql_errors(feeds: MockFeeds) -> None:
    with pytest.raises(ConnectorError, match="rejected"):
        list(
            OpenCTIConnector(
                "http://x.invalid", "wrong", client=feeds.client(), allow_http=True
            ).fetch(EPOCH)
        )
    err = httpx.Client(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"errors": [{"message": "boom"}]})
        )
    )
    with pytest.raises(ConnectorError, match="boom"):
        list(OpenCTIConnector("http://x.invalid", "t", client=err, allow_http=True).fetch(EPOCH))


# ----------------------------------------------------------------------------- shared HTTP helpers


def test_validate_base_url_rules() -> None:
    assert validate_base_url("https://misp.example.org/", False) == "https://misp.example.org"
    with pytest.raises(ConnectorError):
        validate_base_url("http://misp.example.org", False)
    assert validate_base_url("http://localhost:8080", True) == "http://localhost:8080"
    for bad in ("ftp://x.example.org", "https://user:pw@x.example.org", "not a url", "https://"):
        with pytest.raises(ConnectorError):
            validate_base_url(bad, True)


def test_retry_with_backoff_then_success() -> None:
    calls = {"n": 0}
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503) if calls["n"] < 3 else httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    resp = request_with_retry(client, "GET", "http://x.invalid/", sleep=sleeps.append)
    assert resp.status_code == 200 and calls["n"] == 3 and len(sleeps) == 2


def test_retry_gives_up_and_honours_retry_after() -> None:
    sleeps: list[float] = []
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(429, headers={"Retry-After": "7"}))
    )
    with pytest.raises(ConnectorError, match="failed after"):
        request_with_retry(client, "GET", "http://x.invalid/", attempts=3, sleep=sleeps.append)
    assert sleeps and sleeps[0] == 7.0


def test_transport_errors_are_retried() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = httpx.Client(transport=httpx.MockTransport(boom))
    with pytest.raises(ConnectorError):
        request_with_retry(client, "GET", "http://x.invalid/", attempts=2, sleep=lambda s: None)


# ----------------------------------------------------------------------------- factory


def test_build_connectors_requires_configuration_and_blocks_fixtures_in_prod() -> None:
    with pytest.raises(ConnectorError, match="MISP"):
        build_connectors(make_settings(), ["misp"])
    with pytest.raises(ConnectorError, match="OpenCTI"):
        build_connectors(make_settings(), ["opencti"])
    with pytest.raises(ConnectorError, match="unknown"):
        build_connectors(make_settings(), ["splunk"])
    prod = make_settings(env="prod", store_backend="pgvector", auth_mode="apikey")
    with pytest.raises(ConnectorError, match="fixtures"):
        build_connectors(prod, ["fixtures"])
    configured = make_settings(misp_url="https://misp.example.org", misp_api_key="k")
    assert build_connectors(configured, ["misp"])[0].name == "misp"
    assert json.dumps(make_settings().misp_trusted_org_set, default=list) == "[]"
