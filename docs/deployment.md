# Deployment runbook

> **Status: not deployed.** Everything below is the procedure for deploying to AWS. The Terraform and
> workflows have been statically checked (custom reference checker, Checkov, actionlint) but have **never
> been planned or applied**, so expect to fix small issues on the first run (most likely IAM permission
> gaps in the deploy role — see "First-apply expectations").

## 0. Prerequisites you must provide

| Need | Why |
|---|---|
| An AWS account (one per environment is best; one account with two environments also works) and an administrator identity for the **one-time bootstrap** | creates state bucket, ECR repos, OIDC provider and roles |
| **Bedrock model access** enabled in the target region for the Titan embedding model and the Claude model/inference profile in `variables.tf` | otherwise ingest and queries fail with `AccessDeniedException` |
| A **domain name** you control. Either a Route 53 hosted zone (Terraform creates and validates the certificate) or an existing **ACM certificate ARN** | the ALB only serves HTTPS |
| The **CIDR ranges allowed to reach the API** (VPN/corporate egress, SOC tooling) | the ALB security group is closed by default |
| A GitHub repository with Actions enabled | the pipeline |
| MISP and/or OpenCTI base URLs, read-only credentials, and the servers' egress CIDRs | ingestion (optional until you have feeds) |
| Terraform ≥ 1.10 on the administrator's machine | bootstrap |

## 1. Bootstrap the AWS account (once, by an administrator)

```bash
cd infrastructure/terraform/bootstrap
terraform init
terraform apply -var github_repository=OWNER/REPO        # add -var aws_region=... if not us-east-1
terraform output
```

This creates the KMS-encrypted, versioned, TLS-only **state bucket**, one **ECR repository per environment**
(immutable tags, scan on push), the **GitHub OIDC provider**, a read-only **plan role** and one **deploy role
per environment** trusted only for `repo:OWNER/REPO:environment:<env>`.

Bootstrap state is local by default. After the first apply you may migrate it into the new bucket
(`terraform init -migrate-state` with an `s3` backend block using a `tirag/bootstrap/` key) — keep it out of
the key prefixes the deploy roles can write (`tirag/staging/`, `tirag/prod/`).

## 2. Configure GitHub

Create two **environments**, named exactly `staging` and `prod` (the names are part of the AWS trust
policy). On `prod`: *required reviewers*, optionally a wait timer, and restrict deployment branches to
`main`. Then set:

| Scope | Name | Type | Value |
|---|---|---|---|
| Environment `staging` / `prod` | `AWS_DEPLOY_ROLE_ARN` | variable | `deploy_role_arns["staging"]` / `["prod"]` from the bootstrap output |
| Environment | `TF_STATE_BUCKET` | variable | `state_bucket` output |
| Environment | `AWS_REGION` | variable | region (default `us-east-1`) |
| Environment | `TIRAG_TFVARS_JSON` | variable | non-secret deployment settings, e.g. `{"domain_name":"tirag.example.org","alb_ingress_cidrs":["198.51.100.0/24"],"route53_zone_id":"Z…","misp_url":"https://misp.example.org","misp_trusted_orgs":"MY-CSIRT","feed_egress_cidrs":["203.0.113.10/32"],"alarm_email":"secops@example.org"}` |
| Environment (optional, **set only after the first ingest**) | `SMOKE_BASE_URL`, `SMOKE_QUESTION` + secret `TIRAG_SMOKE_API_KEY` | variables + secret | enables the HTTP smoke test. It asserts a non-empty index and a grounded, cited answer to `SMOKE_QUESTION` (a question your real corpus can answer, for a key whose TLP ceiling allows it). The runner's IP must be inside `alb_ingress_cidrs`, or use a self-hosted runner |
| Repository (optional) | `AWS_PLAN_ROLE_ARN`, `TF_STATE_BUCKET`, `TIRAG_PLAN_TFVARS_JSON` | variables | enables the read-only Terraform plan comment on pull requests |

Branch protection on `main`: require the `CI` checks, require review (set real owners in
`.github/CODEOWNERS`), disallow force pushes. Enable GitHub secret scanning and push protection.

## 3. First deployment

Merge to `main` (or run **Deploy** manually). The pipeline:

1. **CI** — lint, tests with coverage gate, RAG evaluation gate, Bandit, pip-audit, Trivy, Checkov,
   Terraform fmt/validate, container build + scan + hardened smoke run.
2. **Build** — image built once, Trivy-gated, saved as an artifact.
3. **staging** — OIDC login → push the *same* image to `tirag-staging` (skips if the immutable tag exists)
   → `terraform plan` / `apply` with `image_tag=<git sha>` → run the **db-init** one-off task
   (`CREATE EXTENSION vector`, tables, indexes; idempotent) → wait for `COMPLETED` rollout, matching
   running/desired counts and healthy ALB targets → check the ingest schedule → optional HTTP smoke test.
   Any failure re-points the service at the previous task definition.
4. **prod** — waits for the reviewer approval, then repeats step 3 with `environments/prod.tfvars`.

`terraform plan` fails fast with a clear message if neither `route53_zone_id` nor `certificate_arn` is
set, or if `alb_ingress_cidrs` is empty.

## 4. Manual steps after the first apply

1. **API keys.** Mint keys locally and store only the hashes:
   ```bash
   tirag keygen --name soc-tool --role analyst --max-tlp AMBER --expires 2027-06-30
   # give the printed key to its owner once; put the printed JSON entry into the secret:
   aws secretsmanager put-secret-value --secret-id tirag-prod/api-keys \
     --secret-string '[{"name":"soc-tool","sha256":"…","role":"analyst","max_tlp":"AMBER"}]'
   aws ecs update-service --cluster tirag-prod --service api --force-new-deployment
   ```
2. **Feed credentials** (if `misp_url` / `opencti_url` are set):
   `aws secretsmanager put-secret-value --secret-id tirag-prod/misp-api-key --secret-string '<key>'` (and
   `tirag-prod/opencti-token`). Create **read-only** users/roles on the feed side.
3. **DNS** — if you did not pass `route53_zone_id`, point your domain at the `alb_dns_name` output and make
   sure the ACM certificate (validated beforehand) covers it.
4. **Alerts** — confirm the SNS email subscription (AWS sends a confirmation link).
5. **First ingest** — wait for the schedule, or run the ingest task once with `--full`:
   ```bash
   aws ecs run-task --cluster tirag-prod --launch-type FARGATE \
     --task-definition tirag-prod-ingest \
     --overrides '{"containerOverrides":[{"name":"ingest","command":["ingest","--source","all","--full"]}]}' \
     --network-configuration 'awsvpcConfiguration={subnets=[<private_subnet_ids>],securityGroups=[<ingest_security_group_id>],assignPublicIp=DISABLED}'
   ```
6. **Verify** (section 5).

## 5. Production verification checklist

```bash
KEY=…   # an analyst key
BASE=https://tirag.example.org
curl -fsS $BASE/healthz && curl -fsS $BASE/readyz
TIRAG_SMOKE_API_KEY=$KEY TIRAG_SMOKE_QUESTION='<a question your corpus can answer>' \
  python scripts/smoke_test.py $BASE --production        # black-box checks: HTTPS, headers, auth, grounded answer, injection rejected, docs disabled
curl -s $BASE/v1/stats -H "Authorization: Bearer $KEY" | jq   # documents/chunks indexed, quarantined count
```

Also confirm: the CloudWatch dashboard shows traffic; no alarm is in `ALARM`; `/<name>/ingest` logs contain
`ingest finished` with `errors: []`; an unauthenticated request returns 401; a request without TLS is
redirected; `/docs` returns 404 (disabled in prod). The smoke test does **not** check TLP filtering — verify
it manually once with a known restricted document and a lower-clearance key (the automated TLP-leak checks
run in CI against the fixtures and a real PostgreSQL).

## 6. Rollback

* **Automatic:** the ECS deployment circuit breaker rolls back tasks that never become healthy; the deploy
  workflow re-points the service to the previous task definition if post-deploy verification fails.
* **Manual:** run the **Rollback** workflow with `environment` and a previous `image_tag` (a git SHA that
  still exists in ECR — the last 50 are kept). It goes through the same environment approval and
  verification, and re-aligns Terraform state with what is running.
* **Database:** schema changes are additive (`CREATE … IF NOT EXISTS`), so older images keep working. For
  data problems see `docs/disaster-recovery.md`.

## 7. First-apply expectations (read this)

Because nothing has been applied yet, plan for iteration:

* The deploy role's permissions were written from the resources in the stack, not captured from a successful
  apply. An `AccessDenied` on the first run is likely; add the missing action to
  `modules/github_oidc/main.tf`, re-apply **bootstrap** (administrator), re-run the workflow. Do not widen
  it to `*`.
* `terraform fmt` was not available when the code was written; if CI's fmt check fails, run
  `terraform fmt -recursive infrastructure/terraform` once and commit.
* Provider and action versions were pinned to the latest available when written; Dependabot keeps them
  current.
* The Bedrock guardrail and inference-profile ARNs depend on the account/region; verify
  `llm_model_id`, `llm_foundation_model_id` and `bedrock_inference_regions` in the Bedrock console.

## 8. Tear-down

Production has `deletion_protection` on the load balancer and database and keeps a final snapshot.
To destroy an environment: disable protection (`db_deletion_protection = false`, apply), then
`terraform destroy -var-file=environments/<env>.tfvars -var image_tag=<any>` from an administrator session
(the deploy roles intentionally cannot manage bootstrap resources). Secrets Manager secrets are retained for
their recovery window, and the log/state buckets are never force-destroyed. Bootstrap resources
(`terraform destroy` in `bootstrap/`) must be emptied manually first (state bucket versions, ECR images).
