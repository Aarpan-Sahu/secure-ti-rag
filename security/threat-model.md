# Threat model

Scope: the threat-intelligence RAG service (API, ingestion, vector store, LLM calls) and its AWS
deployment. Method: trust-boundary walk with STRIDE per boundary, plus the LLM-specific risks
(OWASP Top 10 for LLM Applications). Status labels: **implemented** (code/IaC in this repo, covered
by tests unless noted), **partial**, **planned**.

## Assets

1. Threat-intelligence content, including TLP:AMBER / AMBER+STRICT / RED material (confidentiality).
2. Integrity of that content (a poisoned indicator or report can mislead analysts).
3. Credentials: MISP key, OpenCTI token, analyst API keys, the database master credential.
4. Availability of the analyst search/answer service.
5. The audit trail of who asked what.

## Actors

Authenticated analyst (semi-trusted), authenticated admin, anonymous internet user, a malicious or
compromised **feed contributor** (can publish into MISP/OpenCTI), a compromised dependency or CI action,
an attacker with a leaked API key.

## Data flows and trust boundaries

```
 analyst ──TLS──▶ [WAF] ▶ ALB ──▶ API task ──▶ RDS (pgvector)        TB1 internet→edge, TB2 edge→app
                                    │  └────▶ Bedrock (VPC endpoint)   TB3 app→data, TB4 app→LLM
 MISP / OpenCTI ──HTTPS──▶ ingest task ──▶ RDS / Bedrock embeddings    TB5 feed→ingest (untrusted content)
 GitHub Actions ──OIDC──▶ AWS deploy role                               TB6 CI→cloud
```

TB5 is the most important boundary: everything arriving from feeds is **untrusted text** that will later
be placed in front of an LLM.

## Threats and controls

| ID | Threat | Boundary | Controls | Status |
|---|---|---|---|---|
| T1 | **Prompt injection in a query** ("ignore previous instructions…") | TB1 | Weighted regex scorer rejects the request (400) before retrieval; unicode/zero-width/bidi normalisation first; answer path has no tools to abuse | implemented, tested |
| T2 | **Indirect prompt injection via ingested documents** (poisoned report/event) | TB5 | Same scorer applied per chunk at ingest → chunk quarantined and recorded; if every chunk of a document is bad the stale clean copy is deleted; retrieved text is wrapped in `<document>` tags with `<`,`>`,`&` escaped and the system prompt declares it data | implemented, tested (eval: 2 poison cases, 0 leaks) |
| T3 | **Feed poisoning by an untrusted contributor** | TB5 | `TIRAG_MISP_TRUSTED_ORGS` allow-list on the creating organisation; OpenCTI indicators flagged `revoked` are skipped; MISP `to_ids` is recorded so detection-grade and context-only indicators stay distinguishable; the sync cursor only advances after a clean feed read | implemented (allow-list must be configured; empty = trust all) |
| T4 | **TLP / need-to-know bypass** (analyst sees RED data) | TB1/TB3 | Clearance comes from the credential (API key `max_tlp` or OIDC claim), never from the request body; the ceiling is applied inside the store (SQL `WHERE tlp_rank <= …`) on every retrieval channel (vector, lexical, IOC); a key configured without `max_tlp` gets TLP:CLEAR, the most restrictive ceiling | implemented, tested incl. real PostgreSQL |
| T5 | **Data exfiltration through the model output** (markdown image/link beacons, invented IOCs, secrets) | TB4 | Output guardrails strip images/links/HTML, redact IOCs that are in neither the evidence nor the question, redact secret patterns, defang indicators, cap length; answers with no valid citation are withheld; optional Bedrock Guardrail | implemented, tested |
| T6 | **Hallucinated or uncited claims** | TB4 | Citation validation (`[n]` must map to a retrieved chunk), no-evidence short-circuit never calls the LLM | implemented, tested |
| T7 | **Credential theft / replay** | TB1 | Only SHA-256 digests of API keys are configured (constant-time compare, expiry); OIDC RS256/ES256 validation against JWKS; failed-auth throttle per IP; secrets live in Secrets Manager and are injected as task secrets | implemented (OIDC path tested with generated keys, not against a live IdP) |
| T8 | **Abuse / DoS** | TB1 | WAF managed rules + per-IP rate rule; per-principal token bucket; body-size limit (413); bounded query length and `top_k`; autoscaling | implemented (rate limiting is per replica) |
| T9 | **SQL / tsquery injection** | TB3 | Parameterised SQL everywhere; free-text reduced to `[a-z0-9._-]` tokens before building a `tsquery`; identifiers composed with `psycopg.sql` | implemented, tested |
| T10 | **SSRF via configured feed URLs** | TB5 | `validate_base_url` requires https (http only with explicit opt-in) and rejects embedded credentials; ingest security group allows 443 only to configured feed CIDRs | implemented |
| T11 | **Data at rest / in transit exposure** | TB3 | RDS storage + backups + secrets + logs encrypted with a customer-managed KMS key; `rds.force_ssl=1` and `sslmode=verify-full` with the RDS CA bundle; ALB TLS 1.3 policy; HTTP redirected; S3 buckets TLS-only | implemented (unverified on AWS) |
| T12 | **Lateral movement from a compromised task** | TB2/TB3 | Private subnets, no public IPs; API SG egress limited to VPC endpoints, S3 prefix list and RDS; ingest SG egress limited to feed CIDRs; separate task roles (API: invoke models + guardrail; ingest: embeddings only); read-only root filesystem, non-root, all capabilities dropped | implemented |
| T13 | **Supply-chain compromise** (dependency, base image, CI action) | build | Hash-locked requirements installed with `--require-hashes`; pip-audit, Bandit, CodeQL, Trivy (image + fs), Checkov in CI; all Actions pinned to commit SHAs; Dependabot; immutable ECR tags with scan-on-push; image promoted unchanged staging → prod | implemented (SBOM/signing planned) |
| T14 | **CI/CD credential abuse** | TB6 | No long-lived AWS keys; OIDC roles per environment trusted only for `environment:<name>`; prod requires reviewer approval; deploy role has an explicit deny on the bootstrap IAM/OIDC/state resources | implemented; **deploy role is broad** (see limitations) |
| T15 | **Insider misuse / repudiation** | TB1 | Structured audit events per query with principal, role, clearance, `query_sha256`; query text off by default in prod; WAF and ALB logs | implemented (no tamper-evident log sink) |
| T16 | **Poisoned embeddings / vector-store tampering** | TB3 | Writes only from the ingest role path; deterministic chunk ids and content hashes; DB reachable only from the two task security groups | partial (no integrity re-verification job) |
| T17 | **Model denial of wallet** (token-heavy abuse) | TB4 | Query/answer/context length caps, per-principal rate limits, `llm_max_tokens`, timeouts | implemented (no budget alarm on Bedrock spend yet — planned) |

## Mapping to OWASP LLM Top 10

LLM01 prompt injection → T1, T2 · LLM02 insecure output handling → T5 · LLM03 training-data poisoning →
n/a (no training; see T3 for the equivalent retrieval-poisoning risk) · LLM04 model DoS → T8, T17 ·
LLM05 supply chain → T13 · LLM06 sensitive information disclosure → T4, T5 · LLM07 insecure plugin design →
the model has no tools · LLM08 excessive agency → none granted · LLM09 overreliance → T6 (citations,
"insufficient evidence" refusals) · LLM10 model theft → n/a (managed model).

## Known limitations and residual risk

* The injection scorer is heuristic. A determined attacker can craft text that scores below the threshold;
  defence in depth (escaping, no tools, output guardrails, citation requirement, Bedrock Guardrail) limits
  impact but does not make injection impossible.
* Chunk-level quarantine also removes neighbouring legitimate lines in the same chunk.
* The offline evaluation set is small (25 cases) and was used while tuning; it is a regression gate, not
  proof of retrieval quality. Quality with real Bedrock embeddings and a real model is unevaluated
  (`tirag eval --live` exists for that).
* The application connects to PostgreSQL with the RDS master credential. A separate least-privilege
  database role is a planned improvement.
* The GitHub deploy role can create the whole stack and therefore holds broad permissions on the services
  Terraform manages; it is protected by environment approval, an explicit deny on bootstrap resources and
  short sessions, but a permission boundary / SCP is recommended.
* Rate limiting is in-process per replica.
* There is no distributed tracing and no tamper-evident audit log sink.
