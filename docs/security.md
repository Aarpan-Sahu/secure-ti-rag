# Security

Companion to `security/threat-model.md` (threats and residual risk). This document lists the controls, where
each lives, and how it is verified. "Tested" means an automated test in this repository exercises it;
"static" means Checkov / review only; nothing here has been exercised on AWS.

## 1. Identity and access

| Control | Where | Verification |
|---|---|---|
| API keys: random 256-bit tokens (`tirag_…`), only SHA-256 digests configured, constant-time comparison, optional expiry, per-key `role` and `max_tlp` | `security/auth.py`, `tirag keygen` | tested |
| OIDC JWT validation (RS256/ES256 via JWKS, issuer + audience, expiry); roles from `tirag-admin` / `tirag-analyst` groups; TLP clearance from a claim | `security/auth.py` | tested with generated keys (not against a real IdP) |
| **TLP ceiling comes from the credential, never from the request**; a key or token without a clearance gets TLP:CLEAR | `rag/chain.py::Clearance`, `store` filters | tested (API + real PostgreSQL) |
| Role separation: `/metrics` admin-only; analysts query/search/stats | `api/app.py` | tested |
| Failed-auth throttle per client IP; token-bucket rate limit per principal | `security/ratelimit.py` | tested (rate limit is per replica) |
| Auth mode `disabled` refused in staging/prod | `config.py` | tested |
| AWS: separate roles for task execution, API task, ingest task, scheduler, RDS monitoring, backup, VPC flow logs | `modules/app/iam.tf`, `modules/database`, `modules/network` | static |
| GitHub → AWS via OIDC (no static keys), role per environment trusted for `environment:<name>`, prod behind reviewer approval, 1-hour sessions | `modules/github_oidc` | static |

## 2. Network

* Three subnet tiers; RDS has no internet route and no public address; tasks have no public IPs.
* Security groups reference each other (ALB → API 8080 → RDS 5432); the API group's egress is limited to the
  VPC range (endpoints), the S3 prefix list and RDS. The ingest group adds 443 to `feed_egress_cidrs` only.
* Interface endpoints for ECR, Logs, Secrets Manager and Bedrock Runtime; S3 gateway endpoint.
* ALB: TLS 1.3/1.2 policy `ELBSecurityPolicy-TLS13-1-2-2021-06`, HTTP → HTTPS redirect, invalid headers
  dropped, strictest desync mitigation, access logs to a TLS-only, encrypted, lifecycle-managed bucket,
  ingress limited to `alb_ingress_cidrs` (0.0.0.0/0 needs the explicit `allow_public_internet` opt-in).
* WAFv2: per-IP rate rule plus AWS managed Common, Known-Bad-Inputs (includes Log4Shell), IP-reputation and
  anonymous-IP groups; logs redact the `Authorization` header.
* NACL on the data subnets admits PostgreSQL only from the app subnets.
* Default security group is emptied; VPC flow logs enabled.

## 3. Data protection

* **At rest:** customer-managed KMS key (rotation on) for RDS storage, snapshots/backups, Performance
  Insights, Secrets Manager, CloudWatch log groups, SNS and the AWS Backup vault; ECR and Terraform state use
  the bootstrap key.
* **In transit:** `rds.force_ssl=1` and `sslmode=verify-full` with the RDS CA bundle baked into the image;
  TLS to feeds with verification mandatory in staging/prod; TLS to Bedrock via the VPC endpoint.
* **Secrets:** never in source, images or state. RDS manages its master password; other secrets are
  Secrets Manager containers with fail-closed placeholders and out-of-band values; injected with ECS
  `valueFrom`. `.env` is git-ignored and `.env.example` holds no real values; Trivy and Checkov scan for
  secrets in CI.
* **Privacy of queries:** the audit log stores a SHA-256 and length of each question, not its text; prod
  refuses `TIRAG_AUDIT_LOG_QUERIES=true`.
* **Classification:** every chunk carries its TLP; the most restrictive marking of an object wins; the
  ceiling is applied inside the SQL/memory-store query on all three retrieval channels.

## 4. Application security

* Strict pydantic request models (unknown fields rejected), bounded lengths and `top_k`, body-size cap
  (413) enforced on streamed bodies, request ids sanitised.
* Secure response headers: `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `Cache-Control: no-store`, a
  deny-all CSP, HSTS, permissions policy, CORP; interactive docs disabled in prod.
* Parameterised SQL only; free text reduced to `[a-z0-9._-]` tokens before becoming a `tsquery`.
* Feed URLs validated (https, no embedded credentials); HTTP redirects are not followed (so a feed cannot bounce the connector to another host); bounded retries.
* Errors never expose stack traces or upstream details (`502 upstream service unavailable`).
* Container: non-root numeric UID, read-only root filesystem, capabilities dropped, no shell entrypoint,
  health check, no secrets baked in.

## 5. AI security

| Risk | Control |
|---|---|
| Direct prompt injection | Weighted injection scoring on the query (reject at threshold) after unicode normalisation |
| Indirect injection via feed content | Same scoring per chunk at ingest → quarantine; stale clean copy deleted when a document is fully quarantined; `<document>` isolation with escaping; system prompt declares evidence untrusted |
| Excessive agency | The model has **no tools** and no network access of its own |
| Exfiltration / output handling | Citations required; ungrounded IOCs redacted; markdown links/images and HTML stripped; secret patterns redacted; indicators defanged; length capped |
| Hallucination | No-evidence short-circuit (LLM not called); invalid citations removed; uncited answers withheld |
| Cross-clearance leakage | TLP filter in the store; model only ever receives chunks the caller may see |
| Provider-side safety | Optional Bedrock Guardrail (prompt-attack, harmful content, credential masking) created by Terraform |
| Evaluation | `tirag eval` gates CI on hit-rate, **zero** TLP leaks and **zero** poison leaks |

## 6. Supply chain and pipeline

Hash-locked requirements installed with `--require-hashes` (also inside the Docker build); pip-audit,
Bandit, CodeQL, Trivy (filesystem + image), Checkov (Terraform, Dockerfile, workflows) in CI; every GitHub
Action pinned to a commit SHA with Dependabot updates; workflow `permissions: contents: read` by default;
`persist-credentials: false`; immutable ECR tags with scan-on-push; one image promoted unchanged through
environments; deploy concurrency lock; reviewer approval for prod.

## 7. Audit and detection

Structured JSON logs with request ids; audit events `query`, `query_blocked`, `query_error`, `search`,
`search_blocked` with principal, role, clearance and query hash; alarms on auth-failure spikes, injection
spikes, WAF block spikes and ingest quarantine/errors (`monitoring/README.md`). **Not provided:** CloudTrail
configuration, GuardDuty, Security Hub, a tamper-evident log archive — enable them at the account level
(recommended: CloudTrail with data events for the state bucket and Secrets Manager).

## 8. Incident playbooks (short)

* **Leaked or suspect API key:** remove its entry from the `tirag-<env>/api-keys` secret (or shorten
  `expires`), force a new deployment, mint a replacement, search `principal` in the audit log for its use.
* **Leaked feed credential:** rotate on the MISP/OpenCTI side, `put-secret-value`, force a new ingest run.
* **Suspected feed poisoning:** check `quarantined` in `/v1/stats`; tighten `misp_trusted_orgs`; identify and
  remove offending documents at the source; run `ingest --full` (replaces affected documents).
* **Injection campaign:** `injection-attempt-spike` alarm → find the principal in audit logs → revoke the key.
* **Compromised deploy path:** disable the environment's deploy role (detach its policies or edit the trust
  policy in bootstrap), rotate anything the pipeline can read, review CloudTrail.

## 9. Known limitations (be aware before relying on this)

* Injection detection is heuristic; other controls bound the impact but do not eliminate it.
* The application connects with the RDS master credential; a least-privilege DB role is planned.
* The GitHub deploy role is broad over the services Terraform manages (mitigated by approval, deny on
  bootstrap resources and short sessions). Add a permission boundary or SCP.
* Rate limiting is per replica, not global.
* No SBOM or image signing; no tracing; no tamper-evident audit sink; no Bedrock spend alarm.
* Connectors and the Bedrock path have not been exercised against live systems.
* Everything in `infrastructure/` and `.github/` is statically checked only.
