#!/usr/bin/env python3
"""Minimal concurrent load test for /v1/query and /v1/search (no extra dependencies).

    TIRAG_SMOKE_API_KEY=... python scripts/loadtest.py http://127.0.0.1:8080 \
        --requests 300 --concurrency 16 --endpoint search

NOTE: the per-principal rate limiter (TIRAG_RATE_LIMIT_PER_MINUTE / _BURST) will answer 429 once the
bucket is empty. For a load test, run the target with a raised limit; 429s are reported separately
and are not counted as server errors. Never point this at a production LLM-backed endpoint without
budgeting for the model cost (each /v1/query call invokes the LLM).
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

QUESTIONS = [
    "Which malware does STORMVEIL use for initial access?",
    "What command and control infrastructure does GLASSLOADER use?",
    "How does NIGHT KESTREL abuse cloud access keys?",
    "Is 198.51.100.23 malicious?",
    "What is HERONSHELL?",
    "What mitigations are recommended against ISO phishing attachments?",
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("base_url")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--endpoint", choices=["query", "search"], default="query")
    args = parser.parse_args()

    key = os.environ.get("TIRAG_SMOKE_API_KEY")
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    url = f"{args.base_url.rstrip('/')}/v1/{args.endpoint}"
    results: list[tuple[int, float]] = []

    def one(i: int) -> tuple[int, float]:
        with httpx.Client(timeout=60.0) as client:
            t0 = time.perf_counter()
            try:
                status = client.post(
                    url, json={"question": QUESTIONS[i % len(QUESTIONS)]}, headers=headers
                ).status_code
            except httpx.HTTPError:
                status = 0
            return status, time.perf_counter() - t0

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(one, range(args.requests)))
    wall = time.perf_counter() - started

    ok = [t for s, t in results if s == 200]
    limited = sum(1 for s, _ in results if s == 429)
    errors = sum(1 for s, _ in results if s not in (200, 429))
    print(f"endpoint=/v1/{args.endpoint} requests={args.requests} concurrency={args.concurrency}")
    print(
        f"ok={len(ok)} rate_limited={limited} errors={errors} wall={wall:.1f}s rps={len(results) / wall:.1f}"
    )
    if ok:
        ok.sort()
        pct = lambda p: ok[min(len(ok) - 1, int(len(ok) * p))] * 1000  # noqa: E731
        print(
            f"latency ms: p50={pct(0.50):.0f} p95={pct(0.95):.0f} p99={pct(0.99):.0f} "
            f"mean={statistics.mean(ok) * 1000:.0f} max={ok[-1] * 1000:.0f}"
        )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
