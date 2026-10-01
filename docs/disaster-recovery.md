# Backup and disaster recovery

> **None of this has been exercised.** The targets below follow from the design and AWS-documented
> behaviour; they are objectives to be proven in a drill, not measured results. Run the drills in the last
> section in staging before relying on any number.

## What needs protecting

| Data | Where | Recreatable? |
|---|---|---|
| Vector index (`ti_chunks`) | RDS PostgreSQL | **Yes** — it is derived data. `tirag ingest --full` rebuilds it from MISP/OpenCTI (time depends on feed size and Bedrock embedding throughput) |
| Sync cursor, quarantine log (`ti_sync_state`, `ti_quarantine`) | RDS | Cursor: yes (full re-read). Quarantine history: no (diagnostic only) |
| API-key hashes, feed credentials | Secrets Manager | Re-mint / re-issue; secrets have a 30-day (prod) recovery window after deletion |
| Infrastructure definition | Git + Terraform state (versioned S3) | Yes |
| Images | ECR (last 50 tags kept) + rebuildable from Git | Yes |
| Logs / audit trail | CloudWatch Logs (retention 365 d in prod), ALB log bucket | No — not replicated cross-region |

The source of truth for intelligence is **MISP/OpenCTI**, not this service. The primary DR strategy for the
index is therefore *rebuild from source*; database backups mainly shorten recovery and protect the
non-derived tables.

## Protection in place (Terraform, unverified on AWS)

* RDS **Multi-AZ** in prod (synchronous standby, automatic failover); single-AZ in staging.
* RDS **automated backups** with point-in-time recovery, `db_backup_retention_days` = 14 (prod) / 7 (staging);
  final snapshot on deletion when deletion protection is on; `copy_tags_to_snapshot`.
* **AWS Backup** plan: daily recovery points kept 35 days and weekly kept 180 days in a KMS-encrypted vault;
  failed backup/restore jobs notify the alarm SNS topic.
* Two NAT gateways in prod so egress survives an AZ failure; tasks spread across the configured AZs.
* Terraform state bucket: versioning on, KMS, TLS-only, no force-destroy; noncurrent versions kept 90 days.
* Deletion protection on the database and load balancer in prod; KMS keys have a 30-day deletion window.

## Objectives (proposed)

| Failure | RTO | RPO | Mechanism |
|---|---|---|---|
| Task / container crash | minutes | 0 | ECS replaces tasks; health checks; circuit breaker |
| Availability-zone loss | ≤ 5 min | 0 (synchronous standby) | RDS Multi-AZ failover (AWS documents typically 1–2 min of unavailability), tasks in the other AZ(s), second NAT |
| Bad deployment | ≤ 15 min | 0 | automatic rollback or **Rollback** workflow |
| Accidental deletion / corruption of data | ≤ 2 h (assumes database under ~50 GB; **unvalidated**) | ≤ 5 min (PITR) | restore to a point in time into a new instance, or rebuild the index from the feeds |
| Whole-index corruption / suspected poisoning | hours (feed size + embedding throughput) | feed-defined (nothing in the index is unique) | truncate and `ingest --full` |
| Region loss | days (manual) | feed-defined for the index; logs lost | re-run bootstrap + Terraform in another region, re-mint secrets, `ingest --full`. **Not automated; no cross-region backup copy today** |

## Recovery procedures

### A. Rebuild the index from the feeds (preferred for data problems)

1. Stop or ignore queries if poisoned content is suspected (`min_count = 0` / clear `alb_ingress_cidrs`, apply).
2. Remove the offending content at the source (MISP/OpenCTI).
3. Truncate the index (needs database access — see `operations.md` on ad-hoc SQL): `TRUNCATE ti_chunks, ti_quarantine;
   DELETE FROM ti_sync_state;`
4. Run the ingest task with `--full` (`docs/deployment.md` §4 step 5) and watch `ingest finished`.
5. Verify (`/v1/stats`, smoke test), restore traffic.

### B. Point-in-time restore of the database

1. Choose the restore time (before the incident). In the console or CLI:
   `aws rds restore-db-instance-to-point-in-time --source-db-instance-identifier tirag-prod-pg
   --target-db-instance-identifier tirag-prod-pg-restore --restore-time <UTC time> --db-subnet-group-name tirag-prod-db
   --vpc-security-group-ids <db sg> --no-publicly-accessible`
   (or restore an AWS Backup recovery point / RDS snapshot the same way).
2. The restored instance gets a new endpoint and its own credentials handling; confirm the data
   (`SELECT count(*) FROM ti_chunks`) via a temporary access path.
3. Cut over: the supported path is to make Terraform own the restored instance (`terraform state rm` the
   old database resource and `terraform import` the restored one after aligning identifiers), or to rename
   instances (rename the broken one, then rename the restore to `tirag-prod-pg`) and apply so Terraform sees
   no drift. Both are delicate — practise in staging first, and keep the old instance until verified.
4. Force a new API deployment (new connections), run the smoke test.

### C. Region loss

1. Pick the recovery region; run `bootstrap` there (new state bucket, ECR, OIDC roles) and update the GitHub
   environment variables (`AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`, `TF_STATE_BUCKET`).
2. Enable Bedrock model access in that region; check `llm_model_id` / inference-profile regions.
3. Deploy via the pipeline (new image push + apply), re-mint API keys, set feed credentials.
4. Run `ingest --full`; repoint DNS (`route53_zone_id`-managed records follow the stack).

### D. Loss of secrets

Re-mint API keys (`tirag keygen`) and re-issue feed credentials. A deleted secret can be restored within its
recovery window (`aws secretsmanager restore-secret`). The RDS master secret is managed by RDS and can be
rotated or re-generated from the RDS console.

## Gaps (planned, not implemented)

Cross-region copy of AWS Backup recovery points and of the audit logs; a warm standby region;
automated restore testing; a least-privilege database role (so a compromised API task cannot drop tables);
S3 replication for the state bucket; a `tirag` CLI for quarantine/index inspection.

## Drills (do these in staging before production)

| Drill | Frequency | Pass criteria |
|---|---|---|
| Kill all API tasks | quarterly | service recovers and alarms clear within ~5 min |
| Force an RDS failover (`aws rds reboot-db-instance --force-failover`) in a Multi-AZ environment | quarterly | API reconnects without manual action; record the actual downtime and update the table above |
| PITR restore into a scratch instance and compare row counts | quarterly | restore completes; record the real duration → this becomes the measured RTO |
| Truncate + `ingest --full` | twice a year | index rebuilt; eval/smoke pass; record duration |
| Roll back a deployment with the **Rollback** workflow | monthly | previous tag serving traffic, Terraform state aligned |
| Rotate every secret | twice a year | no outage |
