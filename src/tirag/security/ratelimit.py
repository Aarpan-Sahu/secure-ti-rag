"""Per-principal token-bucket rate limiter (in-process).

With several API replicas each holds its own buckets, so the effective ceiling is
``replicas x limit``. The ALB-level AWS WAF rate rule (see ``infrastructure/``) provides the
global, per-IP ceiling; this limiter protects the LLM budget per authenticated principal.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self,
        per_minute: int,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
        max_buckets: int = 10_000,
    ) -> None:
        self._rate = per_minute / 60.0
        self._burst = float(burst)
        self._clock = clock
        self._max_buckets = max_buckets
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, float]:
        """Return ``(allowed, retry_after_seconds)``."""
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self._burst, now))
            tokens = min(self._burst, tokens + (now - last) * self._rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                self._evict_if_needed()
                return True, 0.0
            self._buckets[key] = (tokens, now)
            return False, (1.0 - tokens) / self._rate

    def _evict_if_needed(self) -> None:
        if len(self._buckets) > self._max_buckets:
            oldest = sorted(self._buckets.items(), key=lambda kv: kv[1][1])[
                : self._max_buckets // 10
            ]
            for key, _ in oldest:
                self._buckets.pop(key, None)
