"""Connector protocol and shared HTTP helpers (retries, URL validation)."""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Protocol
from urllib.parse import urlparse

import httpx

from tirag.models import ThreatDoc

log = logging.getLogger(__name__)

_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


class ConnectorError(RuntimeError):
    """Raised when a feed cannot be read (auth failure, schema error, retries exhausted)."""


class Connector(Protocol):
    name: str
    skipped: int  # documents deliberately not ingested (e.g. untrusted creator org)

    def fetch(self, since: datetime) -> Iterator[ThreatDoc]: ...


def validate_base_url(url: str, allow_http: bool) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ConnectorError(f"invalid feed URL: {url!r}")
    if parsed.scheme == "http" and not allow_http:
        raise ConnectorError("feed URL must use https outside dev/test")
    if parsed.username or parsed.password:
        raise ConnectorError("credentials must not be embedded in the feed URL")
    return url.rstrip("/")


def request_with_retry(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    attempts: int = 4,
    sleep: Callable[[float], None] = time.sleep,
    **kwargs: object,
) -> httpx.Response:
    """HTTP request with bounded exponential back-off on 429/5xx and transport errors."""
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            response = client.request(method, url, **kwargs)  # type: ignore[arg-type]
        except httpx.TransportError as exc:
            last_error = exc
        else:
            if response.status_code not in _RETRY_STATUS:
                return response
            last_error = ConnectorError(f"{url} returned HTTP {response.status_code}")
            retry_after = response.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                sleep(min(float(retry_after), 30.0))
                continue
        if attempt < attempts - 1:
            sleep(min(2**attempt, 20) + random.uniform(0, 0.25))  # noqa: S311 - jitter only
    raise ConnectorError(f"request to {urlparse(url).netloc} failed after {attempts} attempts") from last_error
