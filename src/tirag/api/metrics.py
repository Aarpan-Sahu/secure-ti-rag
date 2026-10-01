"""Prometheus metrics (served at ``/metrics`` to admins only)."""

from __future__ import annotations

from prometheus_client import Counter, Histogram

HTTP_REQUESTS = Counter(
    "tirag_http_requests_total", "HTTP requests", ["method", "route", "status"]
)
HTTP_LATENCY = Histogram(
    "tirag_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "route"],
    buckets=(0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
QUERIES = Counter("tirag_queries_total", "RAG queries by outcome", ["outcome"])
RETRIEVED_CHUNKS = Histogram(
    "tirag_retrieved_chunks", "Chunks passed to the LLM per query", buckets=(0, 1, 2, 4, 8, 12, 20)
)
GUARDRAIL_FLAGS = Counter("tirag_guardrail_flags_total", "Guardrail events", ["flag"])
AUTH_FAILURES = Counter("tirag_auth_failures_total", "Authentication / authorisation failures", ["reason"])
RATE_LIMITED = Counter("tirag_rate_limited_total", "Requests rejected by the rate limiter")
UPSTREAM_ERRORS = Counter("tirag_upstream_errors_total", "LLM / retrieval backend errors")
