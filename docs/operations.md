# Operations

Routine tasks and runbooks. Names assume environment `prod` (`tirag-prod`); substitute `staging`.

## Daily / weekly

* Glance at the CloudWatch dashboard `tirag-prod` and the alarm list; the SNS email is the primary signal.
* Weekly: `GET /v1/stats` (document/chunk counts, quarantined count) — a sudden drop or jump in documents or
  a growing quarantine count deserves a look at the ingest log.
* Weekly: merge Dependabot PRs (CI gates them); check Trivy/CodeQL findings.
* Monthly: review API keys and their expiry; review the WAF and auth-failure trends; test a rollback in
  staging; check the AWS Backup vault shows recent recovery points.
* Quarterly: restore drill (`docs/disaster-recovery.md`), rotate feed credentials, review IAM and security-group
  rules, revisit SLO thresholds.

## Access management

Mint a key (locally; the key is shown once):

```bash
tirag keygen --name <owner-or-tool> --role analyst --max-tlp GREEN --expires 2027-06-30
```

Add the printed JSON object to the list stored in `tirag-prod/api-keys` (read the current value, append,
`put-secret-value`), then `aws ecs update-service --cluster tirag-prod --service api --force-new-deployment`.
Revoke by deleting the entry. Use the lowest `max_tlp` that the consumer needs (`CLEAR` < `GREEN` < `AMBER` <
`AMBER+STRICT` < `RED`). Prefer OIDC (`TIRAG_AUTH_MODE=oidc`) for human users; groups `tirag-analyst` /
`tirag-admin` and a clearance claim drive role and TLP.

## Ingestion

* Schedule: `ingest_schedule` (default hourly in prod, 6-hourly in staging). The job reads the stored cursor
  (10-minute overlap) so runs are incremental and idempotent.
* Run now / re-read everything: `aws ecs run-task … --overrides '{"containerOverrides":[{"name":"ingest","command":["ingest","--source","all","--full"]}]}'`
  (full command in `docs/deployment.md` §4).
* Pause: set `ingest_schedule = ""` and apply (or disable the schedule `tirag-prod-ingest` in the console
  temporarily; Terraform will re-enable it on the next apply).
* Watch: Logs group `/tirag-prod/ingest`, message `ingest finished` with a per-source report
  (`documents_seen/indexed/skipped`, `chunks_indexed/quarantined`, `errors`). Alarms: `ingest-errors`,
  `ingest-stale`.
* **Quarantine.** `/v1/stats` reports the count. Details are in the `ti_quarantine` table (`doc_id`,
  `chunk_idx`, `reason`, short `preview`). The stack provides no bastion or ECS Exec, so ad-hoc SQL needs
  a temporary access path you create (e.g. an SSM-managed instance in the app subnets added to the DB
  security group for the duration of the investigation); a `tirag quarantine` CLI is planned.
  Quarantine is a signal: either a feed contributor is attacking you or a legitimate report quotes an
  attack string — fix at the source, then `--full`.
* Feed credential rotation: rotate in MISP/OpenCTI → `put-secret-value` on `tirag-prod/misp-api-key` /
  `opencti-token` → the next scheduled run uses it (tasks read secrets at start).

## Deploying and rolling back

Normal change: PR → CI → merge → staging → approval → prod (`docs/deployment.md`). Emergency rollback:
**Rollback** workflow with the last good image tag. To stop traffic entirely, set `desired_count = 0` /
`min_count = 0` and apply, or clear `alb_ingress_cidrs`.

## Scaling and capacity

* API: autoscaling on CPU (60 %) and ALB requests per target (300); `min_count`/`max_count` in tfvars. Each
  task is 0.5 vCPU / 1 GiB by default. The `latency-p95` alarm usually points at Bedrock or the database,
  not task count.
* Database: `db_instance_class`, `db_allocated_storage` (autoscaling to `db_max_allocated_storage`). HNSW index
  builds are memory-hungry; scale the class before a large re-embedding. Watch `rds-cpu-high`,
  `rds-storage-low`, `rds-connections-high` (pool max is 10 per task; 6 tasks → 60 connections).
* Bedrock quotas (requests/tokens per minute) throttle under load; `UpstreamErrors` / 502s are the symptom.
  Request quota increases before onboarding many users.

## Maintenance

* **Patching:** images are rebuilt and redeployed on every merge; Dependabot raises base-image and dependency
  updates weekly. RDS minor versions auto-upgrade in the maintenance window (Sun 04:30–05:30 UTC); major
  upgrades are a planned change (snapshot first).
* **Changing the embedding model or dimension:** vectors are tied to the model. Plan: create a new table
  (or a new database) with the new dimension, run `ingest --full` into it, switch, then drop the old data.
  Not automated.
* **Database hygiene:** autovacuum is on by default; after bulk deletes run `VACUUM (ANALYZE) ti_chunks`;
  `REINDEX INDEX CONCURRENTLY ti_chunks_vec_idx` if recall degrades.
* **Logs:** retention `log_retention_days` (staging 30, prod 365). ALB logs expire with the same value.

## Cost control

Cost drivers in rough order: NAT gateways, RDS (+Multi-AZ, storage), interface VPC endpoints, ALB, Fargate,
Bedrock, CloudWatch, WAF, KMS/Secrets. Levers: `nat_gateway_count = 1` (loses AZ-independent egress),
smaller or single-AZ RDS outside prod, fewer endpoints (drop `bedrock-runtime` only if you accept NAT egress to
Bedrock), `ingest_schedule`, `top_k`, `llm_max_tokens`, `log_retention_days`, a lower `max_count`. Use AWS Cost
Explorer with the `Project=tirag` / `Environment` tags (applied via provider default tags) and create an AWS
Budgets alert — the stack does not create one. Prices change; check the AWS pricing pages for your region
rather than relying on figures in this repository.

## On-call quick reference

| Page | First look | Doc |
|---|---|---|
| `no-healthy-targets`, `unhealthy-targets` | ECS service events, `/tirag-prod/api` logs, RDS reachability | `troubleshooting.md` |
| `alb-5xx-ratio`, `latency-p95` | `UpstreamErrors`, Bedrock throttling, RDS CPU | `troubleshooting.md` |
| `ingest-errors`, `ingest-stale` | `/tirag-prod/ingest` logs, secrets, feed reachability | `troubleshooting.md` |
| `auth-failure-spike`, `injection-attempt-spike`, `waf-block-spike` | audit events by principal / client IP | `security.md` §8 |
| Backup job failed (SNS) | AWS Backup console | `disaster-recovery.md` |
