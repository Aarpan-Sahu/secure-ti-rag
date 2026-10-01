# Service level indicators and objectives

These are **proposed** objectives for an internal analyst-facing service. No production traffic has
been measured, so none of the targets below has been validated; the only measured numbers in this
repository are sandbox load-test results (see `docs/architecture.md` "Verified results") and they used the
offline extractive stand-in model, not Bedrock.

| # | SLI (how it is measured) | SLO (rolling 30 days) | Source of truth | Alarm |
|---|---|---|---|---|
| 1 | **Availability** – share of `/v1/query` and `/v1/search` requests answered without a 5xx (ALB `HTTPCode_Target_5XX_Count` ÷ `RequestCount`) | 99.5 % | CloudWatch `AWS/ApplicationELB` | `alb-5xx-ratio`, `no-healthy-targets` |
| 2 | **Latency** – p95 `TargetResponseTime` for the API | ≤ 8 s (query path includes one LLM call); search-only ≤ 1 s is tracked via the access log `duration_ms` | CloudWatch + Logs Insights | `latency-p95` |
| 3 | **Freshness** – age of the last completed ingest run | ≤ 3 h while the hourly schedule is enabled (alarm at 6 h) | `IngestRuns` metric filter | `ingest-stale`, `ingest-errors` |
| 4 | **Grounding** – share of answered queries whose answer carries ≥1 valid citation (`tirag_queries_total{outcome="answered"}` vs `no_answer`) | informational; investigate if the `no_answer` share changes abruptly | Prometheus (`/metrics`) once scraped | — |
| 5 | **Confidentiality invariant** – TLP-leak and poison-leak counts in the evaluation set | exactly 0 (a build gate, not a runtime SLI) | `tirag eval` in CI | CI failure |

## Error budget

99.5 % over 30 days is ≈ 3 h 36 min of full unavailability, or the equivalent in failed requests.

* **Budget > 50 % left:** normal change velocity.
* **Budget 10–50 % left:** production deploys need a second reviewer for non-security changes.
* **Budget exhausted:** only reliability and security fixes ship until the budget recovers; write a
  short post-incident review for the cause.

## Why these indicators

* Analysts need a *correct and current* answer more than a fast one, hence the freshness SLO next to
  availability.
* The query path depends on two managed services (RDS, Bedrock). Upstream failures surface as 502 and
  count against availability by design, so the SLO reflects what users experience.
* Security-relevant behaviour (injection blocks, auth failures, WAF blocks) is monitored as signals with
  alarms rather than as SLOs, because a spike is an event to investigate, not a budget to spend.
