data "aws_caller_identity" "current" {}

locals {
  name = "tirag-${var.environment}"

  is_prod = var.environment == "prod"

  # Exactly the Bedrock resources the API task role may invoke: the inference profile in this account
  # plus the foundation model in each region the profile can route to.
  bedrock_llm_arns = concat(
    ["arn:aws:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:inference-profile/${var.llm_model_id}"],
    [for r in var.bedrock_inference_regions : "arn:aws:bedrock:${r}::foundation-model/${var.llm_foundation_model_id}"],
  )
}

# --- encryption key (logs, secrets, RDS, SNS, backups) ----------------------------------------------
data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_109: standard key policy: account root delegates to IAM
  #checkov:skip=CKV_AWS_111: standard key policy: account root delegates to IAM
  #checkov:skip=CKV_AWS_356: key policies always use resource "*" (the key itself)
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }

  statement {
    sid       = "AlarmsPublishToEncryptedTopic"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "backup.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "main" {
  description             = "${local.name} data-at-rest encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "main" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.main.key_id
}

# --- alert topic (created here so database backups and observability can both use it) --------------------
resource "aws_sns_topic" "alarms" {
  name              = "${local.name}-alarms"
  kms_master_key_id = aws_kms_key.main.arn
}

data "aws_iam_policy_document" "alarms_topic" {
  statement {
    sid       = "AllowCloudWatchAndBackup"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alarms.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "backup.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alarms" {
  arn    = aws_sns_topic.alarms.arn
  policy = data.aws_iam_policy_document.alarms_topic.json
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# --- building blocks ---------------------------------------------------------------------------------
module "network" {
  source             = "./modules/network"
  name               = local.name
  vpc_cidr           = var.vpc_cidr
  az_count           = var.az_count
  nat_gateway_count  = var.nat_gateway_count
  region             = var.aws_region
  kms_key_arn        = aws_kms_key.main.arn
  log_retention_days = var.log_retention_days
}

# The image repository lives in ./bootstrap (it must exist, and hold the image, before this stack
# creates the service). This stack only reads it.
data "aws_ecr_repository" "this" {
  name = local.name
}

module "guardrail" {
  source      = "./modules/guardrail"
  name        = local.name
  kms_key_arn = aws_kms_key.main.arn
}

module "database" {
  source                = "./modules/database"
  name                  = local.name
  vpc_id                = module.network.vpc_id
  subnet_ids            = module.network.data_subnet_ids
  kms_key_arn           = aws_kms_key.main.arn
  instance_class        = var.db_instance_class
  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  multi_az              = var.db_multi_az
  backup_retention_days = var.db_backup_retention_days
  deletion_protection   = var.db_deletion_protection
  alarm_topic_arn       = aws_sns_topic.alarms.arn
}

module "app" {
  source      = "./modules/app"
  name        = local.name
  environment = var.environment
  region      = var.aws_region
  account_id  = data.aws_caller_identity.current.account_id
  kms_key_arn = aws_kms_key.main.arn

  log_retention_days  = var.log_retention_days
  deletion_protection = local.is_prod

  vpc_id             = module.network.vpc_id
  vpc_cidr           = module.network.vpc_cidr
  public_subnet_ids  = module.network.public_subnet_ids
  app_subnet_ids     = module.network.app_subnet_ids
  s3_prefix_list_ids = module.network.endpoint_prefix_list_ids

  alb_ingress_cidrs = var.alb_ingress_cidrs
  feed_egress_cidrs = var.feed_egress_cidrs
  domain_name       = var.domain_name
  route53_zone_id   = var.route53_zone_id
  certificate_arn   = var.certificate_arn

  image              = "${data.aws_ecr_repository.this.repository_url}:${var.image_tag}"
  ecr_repository_arn = data.aws_ecr_repository.this.arn
  task_cpu           = var.task_cpu
  task_memory        = var.task_memory
  desired_count      = var.desired_count
  min_count          = var.min_count
  max_count          = var.max_count
  ingest_schedule    = var.ingest_schedule

  db_host              = module.database.endpoint_address
  db_port              = module.database.port
  db_name              = module.database.db_name
  db_security_group_id = module.database.security_group_id
  db_master_secret_arn = module.database.master_secret_arn

  llm_model_id       = var.llm_model_id
  embedding_model_id = var.embedding_model_id
  bedrock_model_arns = local.bedrock_llm_arns
  guardrail_id       = module.guardrail.guardrail_id
  guardrail_arn      = module.guardrail.guardrail_arn
  guardrail_version  = module.guardrail.guardrail_version

  misp_url          = var.misp_url
  misp_trusted_orgs = var.misp_trusted_orgs
  opencti_url       = var.opencti_url
}

module "observability" {
  source                  = "./modules/observability"
  name                    = local.name
  region                  = var.aws_region
  alarm_topic_arn         = aws_sns_topic.alarms.arn
  cluster_name            = module.app.cluster_name
  service_name            = module.app.service_name
  alb_arn_suffix          = module.app.alb_arn_suffix
  target_group_arn_suffix = module.app.target_group_arn_suffix
  db_instance_id          = module.database.instance_id
  api_log_group           = module.app.api_log_group
  ingest_log_group        = module.app.ingest_log_group
  ingest_enabled          = module.app.ingest_enabled
  web_acl_name            = module.app.web_acl_name
}
