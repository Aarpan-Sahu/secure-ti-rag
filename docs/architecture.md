# Architecture

This document explains how the system is built and why. Diagrams are in the `README.md`.
Statements marked *(unverified on AWS)* describe infrastructure that has been written and statically
checked but never applied.

## 1. Problem and requirements

Analysts keep threat intelligence in **MISP** (events, attributes, galaxies) and **OpenCTI** (STIX 2.1
objects: indicators, malware, intrusion sets, reports). Finding "what do we know about X" means switching
tools and reading raw objects. The goal is a service that:

1. ingests structured intel from both platforms on a schedule,
2. chunks and embeds IOCs, threat-actor profiles and reports into a vector store for semantic search,
3. orchestrates retrieval and an LLM with LangChain to return **grounded, cited** answers,
4. does so without becoming a way to leak restricted (TLP) intel or to be steered by hostile content.

Non-functional requirements that shaped the design: confidentiality by TLP, integrity of retrieved
content (feeds are semi-trusted), auditability, a small operational footprint, reproducible builds, and
infrastructure as code.

## 2. Components

| Component | Implementation | Notes |
|---|---|---|
| API | FastAPI/uvicorn, pure-ASGI middleware (request id, 413 limit, secure headers, metrics) | `src/tirag/api` |
| Orchestration | LangChain Core LCEL: `RunnableLambda` steps for guard → retrieve → prompt → model → parse → guardrails; custom `BaseRetriever` | `src/tirag/rag/chain.py` |
| Retrieval | `HybridRetriever`: vector + lexical + exact-IOC, weighted Reciprocal Rank Fusion | `src/tirag/rag/retriever.py` |
| Store | `ChunkStore` interface; `PgVectorStore` (production) and `MemoryStore` (dev/CI) | `src/tirag/store` |
| Connectors | `MispConnector` (REST search), `OpenCTIConnector` (GraphQL, cursor pagination) | `src/tirag/connectors` |
| Ingestion | per-document normalise → scan → chunk → embed → atomic replace; sync cursor in DB | `src/tirag/ingest` |
| Models | Embeddings: `hash` (offline stand-in) or Bedrock Titan v2 (1024-d). LLM: `extractive` (offline stand-in), Bedrock Claude (Converse API) or Anthropic API | `embeddings.py`, `llm.py` |
| Security layer | auth, rate limit, sanitisation, injection scoring, IOC handling, output guardrails | `src/tirag/security` |

## 3. Data model

One table, `ti_chunks`, plus `ti_sync_state` (per-source cursor) and `ti_quarantine` (rejected chunks):

* `embedding vector(N)` with an **HNSW** cosine index,
* `tsv tsvector` (generated, `simple` configuration so indicators and codenames are not stemmed) with a **GIN** index,
* `iocs text[]` with a **GIN** index — normalised, refanged IOC values extracted from the chunk,
* `tlp` + `tlp_rank smallint` (0 CLEAR … 4 RED) — the filter column,
* `doc_id` (`source:doc_type:source_id`), `chunk_idx`, `content_hash`, `modified`, `metadata jsonb`.

Chunk ids are deterministic (`uuid5` of doc id, chunk index and content hash), so re-ingesting the same document is
idempotent, and a document update is an **atomic replace** (delete old chunks + insert new, one
transaction) so queries never see half a document.

## 4. Ingestion pipeline

1. **Fetch.** Connectors page through the source using a stored cursor with a 10-minute overlap. The
   cursor advances only after a *clean* read of the whole feed, so a transient failure re-reads rather
   than skips. Retries use bounded exponential back-off on 429/5xx.
2. **Normalise.** Each MISP event / OpenCTI object becomes a `ThreatDoc` with type (`indicator`,
   `threat_actor`, `malware`, `campaign`, `report`, …), title, TLP (most restrictive of the object's
   markings; default configurable), labels, URL back to the source, and IOCs. STIX patterns are parsed for
   observables; OpenCTI `revoked` indicators are dropped; MISP `to_ids` is recorded.
3. **Trust gate.** MISP events whose creating organisation is not on `TIRAG_MISP_TRUSTED_ORGS` are
   skipped when an allow-list is configured.
4. **Clean + scan.** `clean_text` removes zero-width/bidi/control characters, HTML comments and
   `<script>/<style>` blocks; the injection scorer runs per chunk. Suspect chunks are **quarantined**
   (stored in `ti_quarantine` with a short preview, never indexed). If *all* chunks of a document are
   quarantined, any previously indexed clean copy is deleted so a tampered document cannot keep serving
   stale content.
5. **Chunk.** `RecursiveCharacterTextSplitter` (1,000 characters, 150 overlap) for prose; indicator lists
   are chunked by line groups (25 IOCs per chunk) so exact values are never split across chunks. Each chunk
   is prefixed with a one-line header (type, title, source, TLP) so it is self-describing when retrieved alone.
6. **Embed + store.** Batches of 32 through the configured embedder, then `upsert_document`.

## 5. Retrieval

For a question the retriever builds three candidate lists under the **same clearance filter**:

* *vector* — cosine similarity on the HNSW index with a minimum-score cut-off,
* *lexical* — PostgreSQL full-text (`tsquery` of sanitised OR-terms), ranked by `ts_rank_cd`,
* *IOC* — exact match of any IOC present in the question against the `iocs` array.

They are combined with **weighted RRF** (`k = 60`; IOC 3.0, lexical 1.0, vector 1.0) so an exact indicator
hit dominates, then capped at 3 chunks per document for diversity. A **relevance gate** computes
IDF-weighted overlap of the question's concepts (with CTI synonyms such as *C2 ↔ command-and-control*,
*IOC ↔ indicator*) against the candidate pool; if evidence is weak the service answers "insufficient
evidence" **without calling the LLM** — cheaper, faster and impossible to hallucinate from nothing.

Why hybrid: embeddings are good at paraphrase ("how do they steal credentials") but weak at exact
strings (a hash, an IP, a codename), while analysts constantly ask about exact strings.

## 6. Answer generation and guardrails

The prompt (`rag/prompts.py`) states that everything inside `<document>` tags is **untrusted data**, never
instructions. Evidence is escaped (`<`, `>`, `&`) so a document cannot close the tag, and the model is given
no tools. After generation:

* `[n]` markers are validated against the retrieved set; invalid ones are removed; an answer with no valid
  citation is withheld;
* IOCs in the answer that appear in neither the evidence nor the question are redacted;
* markdown images/links and raw HTML are stripped (closing the classic exfiltration-by-URL channel),
  secret-looking strings are redacted, indicators are defanged, length is capped;
* an optional **Bedrock Guardrail** (prompt-attack filter, harmful-content filters, credential masking) is
  attached to every model call.

## 7. AWS deployment *(unverified on AWS)*

```
internet → WAFv2 → ALB (443, TLS 1.3; 80 → 301) → ECS Fargate API ×2..6 (private subnets)
                                                   ├→ RDS PostgreSQL 16 + pgvector (isolated subnets, Multi-AZ in prod)
                                                   └→ Bedrock via VPC endpoint (embeddings, answer model, guardrail)
EventBridge Scheduler → ECS Fargate task `tirag ingest` → feeds (HTTPS, CIDR-allow-listed) → RDS / Bedrock
```

* **Network.** Three tiers (public: ALB + NAT; private: tasks; isolated: RDS with no internet route).
  Interface endpoints for ECR, Logs, Secrets Manager and Bedrock Runtime plus an S3 gateway endpoint mean
  the API task needs **no internet egress**; its security group allows 443 to the VPC range, S3 and 5432
  to the database only. The ingest task's group additionally allows 443 to the configured feed CIDRs
  (through NAT). A network ACL restricts the data tier. VPC flow logs go to an encrypted log group.
* **Compute.** Fargate tasks: non-root UID 10001, read-only root filesystem with a `/tmp` volume, all Linux
  capabilities dropped, init process, health checks, `stopTimeout` 30 s. The service uses a deployment
  circuit breaker with automatic rollback and 100 %/200 % rolling limits; CPU and request-count target
  tracking scale it.
* **Data.** RDS master credentials are generated and rotated by RDS in Secrets Manager (they never appear in
  Terraform state); `rds.force_ssl=1`; encrypted storage, backups, Performance Insights and logs with a
  customer-managed KMS key; AWS Backup daily + weekly plans in addition to PITR.
* **Secrets.** Secret *containers* are Terraform-managed with fail-closed placeholders and
  `ignore_changes`; real values are set out-of-band so they never enter the repo or state. ECS injects them
  via `valueFrom`.
* **IAM.** Execution role (pull image, write logs, read the specific secrets), API task role (invoke the
  configured models and apply the guardrail), ingest task role (embedding model only), scheduler role
  (run that one task definition). GitHub OIDC roles live in the separate `bootstrap` stack so the pipeline
  cannot modify its own identity.
* **Observability.** See `monitoring/README.md`.

### Why these choices (and what was rejected)

| Decision | Rationale | Rejected alternative |
|---|---|---|
| ECS Fargate | One stateless service and one scheduled job; no nodes, no cluster upgrades, task-level IAM and SGs | **EKS** — adds a control plane, node/addon lifecycle and RBAC for no benefit at this size |
| PostgreSQL + pgvector | Vectors, full-text, IOC array and TLP filter in one transactional store; one thing to back up and secure | OpenSearch / a hosted vector DB — second system, second access-control model, TLP filter would have to be re-implemented |
| Bedrock | IAM-authenticated (no API keys), VPC endpoint, guardrails, data stays in the account | Direct third-party API — secrets management and egress to the internet (still supported via `TIRAG_LLM_PROVIDER=anthropic` for dev) |
| Scheduled ingest task | Simple, observable, independent failure domain | Event-driven ingestion — MISP/OpenCTI streams add moving parts; polling with a cursor is adequate |
| API keys + OIDC | Keys work for SOC tooling today; OIDC (e.g. Cognito, Entra, Okta) plugs in for human users | Building a user database |
| Single region, Multi-AZ | RTO/RPO in `docs/disaster-recovery.md` are met without cross-region complexity | Active-passive multi-region — planned only if requirements demand it |

## 8. Verified results (sandbox, not AWS)

| Check | Result |
|---|---|
| Tests | 274 passed, 94.6 % coverage; real PostgreSQL + pgvector (embedded) for 21 store tests |
| Offline evaluation (25 cases) | hit-rate@8 1.00, MRR 0.82, 0 TLP leaks, 0 poison leaks, injection block rate 1.00, refusal accuracy 1.00 |
| Black-box smoke test vs live uvicorn + pgvector | 16/16 |
| Load test (800 requests, 30-chunk corpus, extractive LLM) | 0 errors; query p95 ≈ 0.34 s; search p95 ≈ 0.58 s |

Caveats: the corpus is tiny and fictional; the model and embedder are offline stand-ins (so quality and
latency with Bedrock are **unmeasured**); one eval answer expectation was loosened during tuning; the golden
set is a regression gate, not a benchmark.

## 9. Not implemented / planned

OpenTelemetry tracing; Prometheus scraping and a managed Prometheus/Grafana stack; a least-privilege
database role for the application; cross-region backup copy; SBOM generation and image signing; a CLI to
inspect the quarantine table; distributed rate limiting; a Bedrock spend alarm; automated re-embedding when
the embedding model changes.
