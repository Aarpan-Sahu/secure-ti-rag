from __future__ import annotations

from typing import Any

from tirag.config import Settings
from tirag.connectors.base import Connector, ConnectorError
from tirag.connectors.misp import MispConnector
from tirag.connectors.opencti import OpenCTIConnector


def build_connectors(settings: Settings, sources: list[str]) -> list[Any]:
    """Instantiate the requested connectors. ``fixtures`` uses the in-process mock feeds."""
    connectors: list[Any] = []
    allow_http = settings.env in ("dev", "test")
    for source in sources:
        if source == "misp":
            if not (settings.misp_url and settings.misp_api_key):
                raise ConnectorError("MISP is not configured (TIRAG_MISP_URL / TIRAG_MISP_API_KEY)")
            connectors.append(
                MispConnector(
                    settings.misp_url,
                    settings.misp_api_key.get_secret_value(),
                    verify_tls=settings.misp_verify_tls,
                    trusted_orgs=settings.misp_trusted_org_set,
                    page_size=settings.misp_page_size,
                    default_tlp=settings.default_tlp_label,
                    allow_http=allow_http,
                )
            )
        elif source == "opencti":
            if not (settings.opencti_url and settings.opencti_token):
                raise ConnectorError("OpenCTI is not configured (TIRAG_OPENCTI_URL / TIRAG_OPENCTI_TOKEN)")
            connectors.append(
                OpenCTIConnector(
                    settings.opencti_url,
                    settings.opencti_token.get_secret_value(),
                    verify_tls=settings.opencti_verify_tls,
                    page_size=settings.opencti_page_size,
                    default_tlp=settings.default_tlp_label,
                    allow_http=allow_http,
                )
            )
        elif source == "fixtures":
            if settings.env in ("staging", "prod"):
                raise ConnectorError("synthetic fixtures must not be ingested in staging/prod")
            from tirag.connectors.mock_feeds import fixture_connectors

            connectors.extend(fixture_connectors(settings))
        else:
            raise ConnectorError(f"unknown source: {source}")
    return connectors


__all__ = ["Connector", "ConnectorError", "MispConnector", "OpenCTIConnector", "build_connectors"]
