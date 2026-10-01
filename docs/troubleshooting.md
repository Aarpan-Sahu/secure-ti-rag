# Troubleshooting

Find the symptom, check the cause, apply the fix. Log groups: `/tirag-<env>/api`, `/tirag-<env>/ingest`,
`/tirag-<env>/db-init`. Every API response and log line carries a `request_id`.

## API

| Symptom | Likely cause | Check / fix |
|---|---|---|
| `no-healthy-targets` alarm, ALB 503 | Tasks failing `/readyz` (database unreachable) or crashing at start | ECS console → service → events and stopped-task reasons. Crash at start: Settings validation error in the API log (e.g. `TIRAG_STORE_BACKEND must be 'pgvector'`, missing DB host, OIDC settings incomplete). `CannotPullContainerError`: image tag missing in ECR or the VPC endpoints/S3 route are wrong. `ResourceInitializationError … secrets`: a secret has no value/permission or the KMS key policy blocks it |
| `/readyz` 503 `{"database": false}` | SG, credentials or TLS | Task SG → DB SG on 5432; RDS master secret ARN correct; `verify-full` needs the RDS CA at `/etc/ssl/rds/global-bundle.pem` (baked into the image; a failed `ADD` at build time means the image is bad) |
| 401 on every request | Placeholder secret (`[]`) still in `tirag-<env>/api-keys`, wrong key, hash mismatch, expired key | `tirag keygen` again; make sure the **sha256** (not the key) is in the JSON; force a new deployment after `put-secret-value` (tasks read secrets at start) |
| 403 | Authenticated but role/clearance insufficient | `/metrics` needs `admin`; for OIDC check the groups claim (`tirag-analyst`/`tirag-admin`) and `TIRAG_OIDC_ROLE_CLAIM` |
| 400 `request rejected by input policy` | Injection guard blocked the question | Rephrase; check `flags` in the audit log. A legitimate analyst question that quotes attack phrases may trip the heuristics — raise it as a tuning issue, do not lower the threshold globally |
| 429 | Per-principal rate limit (30/min, burst 10 per replica) or auth-failure throttle | Tune `TIRAG_RATE_LIMIT_*` or fix the noisy client |
| 502 `upstream service unavailable` | Bedrock error/throttle/permission, or DB error | API log around the `request_id`: `AccessDeniedException` → model access not enabled or task-role ARNs wrong (inference profile **and** each regional foundation-model ARN, plus `bedrock:ApplyGuardrail`); `ThrottlingException` → quota; `ValidationException` → model id wrong for the region |
| Answers say "insufficient evidence" | Nothing relevant at the caller's clearance, or index empty | `GET /v1/stats` (chunks > 0?). Lower-clearance keys legitimately see less. Try `/v1/search` with the same question to see what retrieval returns |
| Answer withheld / `flags` contains `no_valid_citation` | The model produced no valid `[n]` citation | Retry; if frequent with a real model, review the prompt and `llm_max_tokens` |
| Slow responses | Bedrock latency, DB CPU, task CPU | Dashboard (target response time p50/p95/p99, ECS CPU, RDS CPU); Bedrock quotas; scale tasks or DB |
| 413 | Body larger than `TIRAG_MAX_BODY_BYTES` (32 KiB) | The client is sending something it shouldn't |
| WAF blocks a legitimate request | A managed rule matched | WAF log group, `terminatingRuleId`; add a scoped rule-group override rather than disabling the group |

## Ingestion

| Symptom | Likely cause | Fix |
|---|---|---|
| Task exits 2 with `error: …` | Connector not configured (missing URL/credential) or URL rejected (http, embedded credentials) | Set `misp_url`/`opencti_url` and the secrets; URLs must be `https://` without user:pass |
| `feed read failed` (alarm `ingest-errors`) | Network (feed CIDR not in `feed_egress_cidrs`, DNS), TLS verification failure, 401/403 from the feed, rate limiting | Task logs show `source` and error. Test reachability from the ingest SG's subnets; confirm the credential is valid and read-only; for private CA feeds add the CA to the image (verification cannot be disabled in staging/prod) |
| Cursor seems stuck / nothing new | Feed has no newer objects, or the previous read failed (cursor only advances after a clean read) | Run once with `--full`; compare `documents_seen` with the source |
| `failed to ingest document` | One malformed document or an embedding error | The run continues with the rest; find `doc_id` in the log; Bedrock embedding errors usually mean quota/permission |
| `chunks_quarantined` > 0 | Injection-like content in a feed document | See `operations.md` (Quarantine) and `security.md` §8 |
| `ingest-stale` alarm | Schedule disabled, task failing to start, or no feeds configured | `aws scheduler get-schedule --name tirag-<env>-ingest`; ECS stopped-task reasons (secrets, image, capacity); recall that the schedule only exists when at least one feed URL is set |
| Embedding dimension error | `TIRAG_EMBEDDING_DIM` does not match the table's vector size | The table was created with a different model/dimension; see "Changing the embedding model" in `operations.md` |

## Infrastructure and pipeline

| Symptom | Cause / fix |
|---|---|
| Deploy workflow: "GitHub environment variable … is not set" | Configure the environment variables listed in `docs/deployment.md` §2 |
| `terraform plan`: precondition failed | Set `route53_zone_id` or `certificate_arn`, and a non-empty `alb_ingress_cidrs` in `TIRAG_TFVARS_JSON` |
| `AccessDenied` during apply | The deploy role lacks an action; add it to `modules/github_oidc/main.tf`, apply **bootstrap** as admin, re-run. (The deny on `gha-tirag-*` roles and the OIDC provider is intentional.) |
| `Could not assume role` / `Not authorized to perform sts:AssumeRoleWithWebIdentity` | The job did not run in the GitHub environment named `staging`/`prod`; repository name in bootstrap differs from the real one; `id-token: write` missing |
| `terraform fmt -check` fails in CI | Run `terraform fmt -recursive infrastructure/terraform` and commit |
| `image already exists` / immutable tag | Expected on re-runs; the workflow skips the push when the tag exists |
| ECS deployment keeps rolling back | Circuit breaker triggered: look at the new tasks' stopped reasons (same list as "API" above) |
| ACM validation hangs | The Route 53 zone is not authoritative for the domain, or `route53_zone_id` is wrong |
| `ResourceAlreadyExists` for a log group / secret after a destroy | Log groups and secrets (30-day recovery window) outlive a destroy; import or restore them, or wait/force-delete the secret |
| Trivy fails the build | A fixable HIGH/CRITICAL vulnerability in the base image or a dependency: rebuild on a newer base, bump the dependency (regenerate the hash-locked requirement files) |
| Checkov fails | Fix, or add a justified inline `#checkov:skip=<ID>: <reason>` reviewed in the PR |

## Local development

| Symptom | Fix |
|---|---|
| `pip install` refuses (hash mismatch / "requires hashes") | Use the lock files exactly: `pip install --require-hashes -r requirements-dev.txt`, then `pip install --no-deps -e .` |
| `ValueError: TIRAG_API_KEYS_JSON is not valid JSON` | Quote the JSON in the shell with single quotes |
| 401 locally | Dev default is `TIRAG_AUTH_MODE=apikey`; set `disabled` for a throwaway local run or mint a key |
| Integration tests fail to start PostgreSQL | They use the `pgserver` wheel (embedded PostgreSQL); run on a non-root user or check disk space/permissions of the temp dir; run unit tests only with `pytest -m "not integration"` |
| Everything answers "insufficient evidence" | The index is empty: `tirag ingest --source fixtures` |
| Answers read like quoted snippets | Expected with `TIRAG_LLM_PROVIDER=extractive` (offline stand-in). Use `bedrock` or `anthropic` for generated prose |
| `docker compose` complains about `TIRAG_DB_PASSWORD` | Intentional: set it in `.env` |
