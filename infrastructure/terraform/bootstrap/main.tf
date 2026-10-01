data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# --- key for state + image repositories ---------------------------------------------------------------
data "aws_iam_policy_document" "bootstrap_key" {
  #checkov:skip=CKV_AWS_109: standard key policy: account root delegates to IAM
  #checkov:skip=CKV_AWS_111: standard key policy: account root delegates to IAM
  #checkov:skip=CKV_AWS_356: standard key policy: account root delegates to IAM
  # Standard "enable IAM policies" statement: access is then granted by IAM identity policies
  # (the deploy roles get kms:Decrypt / GenerateDataKey on this key only).
  statement {
    sid       = "EnableIamPolicies"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "bootstrap" {
  description             = "tirag Terraform state and ECR encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.bootstrap_key.json
}

resource "aws_kms_alias" "bootstrap" {
  name          = "alias/tirag-bootstrap"
  target_key_id = aws_kms_key.bootstrap.key_id
}

# --- Terraform state ------------------------------------------------------------------------------------
resource "aws_s3_bucket" "state" {
  #checkov:skip=CKV_AWS_18: access is audited through CloudTrail data events (recommended in docs/security.md; not created by this repo)
  #checkov:skip=CKV2_AWS_62: no event consumers
  #checkov:skip=CKV_AWS_144: cross-region state replication is a planned DR improvement (docs/disaster-recovery.md)
  bucket        = "tirag-tfstate-${local.account_id}-${var.aws_region}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.bootstrap.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "state" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket     = aws_s3_bucket.state.id
  policy     = data.aws_iam_policy_document.state.json
  depends_on = [aws_s3_bucket_public_access_block.state]
}

# --- image repositories (one per environment) ----------------------------------------------------------
module "ecr" {
  for_each    = toset(var.environments)
  source      = "../modules/ecr"
  name        = "tirag-${each.key}"
  kms_key_arn = aws_kms_key.bootstrap.arn
}

# --- GitHub OIDC federation ----------------------------------------------------------------------------
module "github_oidc" {
  source              = "../modules/github_oidc"
  github_repository   = var.github_repository
  environments        = var.environments
  region              = var.aws_region
  account_id          = local.account_id
  state_bucket_arn    = aws_s3_bucket.state.arn
  state_kms_key_arn   = aws_kms_key.bootstrap.arn
  ecr_repository_arns = { for e, m in module.ecr : e => m.repository_arn }
}
