# Secret *containers* are managed here; the real values are set out-of-band
# (`aws secretsmanager put-secret-value`) and Terraform ignores later changes, so no secret ever
# enters the repository or the state file. The placeholders fail closed: `[]` authenticates nobody,
# and the feed placeholders are rejected by MISP / OpenCTI.

resource "aws_secretsmanager_secret" "api_keys" {
  #checkov:skip=CKV2_AWS_57: values are hashes/tokens issued by us or by MISP/OpenCTI; rotation is a documented manual runbook (docs/operations.md), not a Lambda rotation
  name                    = "${var.name}/api-keys"
  description             = "JSON list of API-key SHA-256 hashes with role + TLP clearance (tirag keygen)"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 7
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id     = aws_secretsmanager_secret.api_keys.id
  secret_string = "[]"
  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "misp" {
  #checkov:skip=CKV2_AWS_57: third-party issued API key; manual rotation runbook in docs/operations.md
  count                   = var.misp_url == "" ? 0 : 1
  name                    = "${var.name}/misp-api-key"
  description             = "MISP automation API key (read-only role)"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 7
}

resource "aws_secretsmanager_secret_version" "misp" {
  count         = var.misp_url == "" ? 0 : 1
  secret_id     = aws_secretsmanager_secret.misp[0].id
  secret_string = "SET-ME-OUT-OF-BAND" # checkov:skip=CKV_SECRET_6: placeholder text, not a credential
  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "opencti" {
  #checkov:skip=CKV2_AWS_57: third-party issued API token; manual rotation runbook in docs/operations.md
  count                   = var.opencti_url == "" ? 0 : 1
  name                    = "${var.name}/opencti-token"
  description             = "OpenCTI API token (read-only user)"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.environment == "prod" ? 30 : 7
}

resource "aws_secretsmanager_secret_version" "opencti" {
  count         = var.opencti_url == "" ? 0 : 1
  secret_id     = aws_secretsmanager_secret.opencti[0].id
  secret_string = "SET-ME-OUT-OF-BAND" # checkov:skip=CKV_SECRET_6: placeholder text, not a credential
  lifecycle {
    ignore_changes = [secret_string]
  }
}
