resource "aws_cloudwatch_log_group" "api" {
  #checkov:skip=CKV_AWS_338: retention is a variable; production sets 365 days in environments/prod.tfvars
  name              = "/${var.name}/api"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_group" "ingest" {
  #checkov:skip=CKV_AWS_338: retention is a variable; production sets 365 days in environments/prod.tfvars
  name              = "/${var.name}/ingest"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_group" "dbinit" {
  #checkov:skip=CKV_AWS_338: retention is a variable; production sets 365 days in environments/prod.tfvars
  name              = "/${var.name}/db-init"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# --- ALB access logs (ALB only supports SSE-S3 buckets) ---------------------------------------------
data "aws_elb_service_account" "this" {}

resource "aws_s3_bucket" "alb_logs" {
  #checkov:skip=CKV_AWS_18: this IS the log bucket; self-logging would be circular
  #checkov:skip=CKV2_AWS_62: no event consumers
  #checkov:skip=CKV_AWS_144: access logs are reproducible diagnostics, replication not required
  #checkov:skip=CKV_AWS_145: ALB access-log delivery only supports SSE-S3 buckets (SSE-KMS is rejected)
  bucket        = "${var.name}-alb-logs-${var.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ALB access-log delivery does not support SSE-KMS; SSE-S3 (AES256) is the only supported option
#trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "alb_logs" {
  statement {
    sid       = "AlbWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/${var.account_id}/*"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.this.arn]
    }
  }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.alb_logs.arn, "${aws_s3_bucket.alb_logs.arn}/*"]
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

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket     = aws_s3_bucket.alb_logs.id
  policy     = data.aws_iam_policy_document.alb_logs.json
  depends_on = [aws_s3_bucket_public_access_block.alb_logs]
}
