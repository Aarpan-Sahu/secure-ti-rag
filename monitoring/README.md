# Monitoring

What is **implemented** (Terraform `modules/observability`, `modules/app`, application code) and what is
**planned** is stated explicitly. Nothing here has run against a live AWS account yet.

## Signals

| Layer | Source | Where it lands | Status |
|---|---|---|---|
| Load balancer | `AWS/ApplicationELB` (requests, 4xx/5xx, target response time, healthy hosts) | CloudWatch metrics, dashboard, alarms | implemented (Terraform) |
| Service | `AWS/ECS` CPU/memory, Container Insights | CloudWatch | implemented (Terraform) |
| Database | `AWS/RDS` CPU, storage, connections; Performance Insights; Enhanced Monitoring; `postgresql` log export | CloudWatch | implemented (Terraform) |
| Edge | `AWS/WAFV2` blocked requests; WAF logs (Authorization header redacted) | CloudWatch Logs `aws-waf-logs-<name>` | implemented (Terraform) |
| Application logs | JSON on stderr: access log (`msg="request"`), audit events (`query`, `query_blocked`, `query_error`, `search`), ingest events | CloudWatch Logs `/<name>/api`, `/<name>/ingest` (KMS encrypted) | implemented (code + Terraform) |
| Log-derived metrics | metric filters → namespace `<name>/app` (`AuthFailures`, `QueriesBlocked`, `UpstreamErrors`, `IngestErrors`, `IngestQuarantined`, `IngestRuns`) | CloudWatch | implemented (Terraform) |
| Prometheus metrics | `/metrics` (admin role only): request count/latency, query outcomes, guardrail flags, auth failures, rate-limit rejections, upstream errors | not scraped by the default stack | endpoint implemented; **scraping is planned** (ADOT sidecar → Amazon Managed Prometheus) |
| Tracing | LangChain runnable names (`guardrails`, …) are set; no OpenTelemetry exporter | — | **not implemented** |
| Backups | AWS Backup job failure → SNS | SNS topic | implemented (Terraform) |

Every log line carries `request_id`; the same id is returned in the `X-Request-ID` header and the API
error body, so a user report can be traced to one request. Query text is **not** logged by default
(`query_sha256` and `query_len` instead).

## Alarms (all notify the `<name>-alarms` SNS topic)

| Alarm | Condition | Meaning / first action |
|---|---|---|
| `alb-5xx-ratio` | >2 % 5xx for 2×5 min | availability SLO burn → check ECS events, `UpstreamErrors`, Bedrock status |
| `no-healthy-targets` | 0 healthy targets for 2 min | outage → `docs/troubleshooting.md` §"API unhealthy" |
| `unhealthy-targets` | ≥1 unhealthy target for 3 min | a task is failing `/readyz` (usually database connectivity) |
| `latency-p95` | p95 > 8 s for 15 min | LLM or database slow; check Bedrock throttling and RDS CPU |
| `ecs-cpu-high`, `ecs-memory-high` | >85 % for 10 min | autoscaling at max or leak |
| `rds-cpu-high`, `rds-storage-low`, `rds-connections-high` | 80 % CPU / <10 GiB free / >100 connections | capacity |
| `ingest-errors` | any `feed read failed` / `failed to ingest document` in 1 h | feed credential, network or format problem; data going stale |
| `ingest-stale` | no `ingest finished` in 6 h | scheduler or task failing; freshness SLO |
| `auth-failure-spike` | >50 401/403 in 5 min | key probing or a broken client |
| `injection-attempt-spike` | >20 blocked queries in 10 min | prompt-injection campaign against the API |
| `waf-block-spike` | >500 WAF blocks in 5 min | scanning / abuse |

Thresholds are starting points chosen from reasoning, not from production history; tune them after the
first weeks of real traffic.

## Useful CloudWatch Logs Insights queries

```
# slowest requests
fields @timestamp, path, status, duration_ms, request_id
| filter msg = "request" and path = "/v1/query"
| sort duration_ms desc | limit 20

# guardrail activity by flag (audit events)
fields @timestamp, event, principal, flags
| filter event in ["query_blocked", "query"] and ispresent(flags)
| stats count() by event

# which principals get the most 401/403
fields principal, status
| filter msg = "request" and status in [401, 403]
| stats count() by client | sort count() desc

# ingest outcome history
fields @timestamp, report.documents_indexed, report.chunks_quarantined, report.errors
| filter msg = "ingest finished"
| sort @timestamp desc | limit 24
```
