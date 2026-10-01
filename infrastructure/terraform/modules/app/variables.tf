variable "name" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "kms_key_arn" { type = string }
variable "log_retention_days" { type = number }

variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "app_subnet_ids" { type = list(string) }
variable "s3_prefix_list_ids" { type = list(string) }

variable "alb_ingress_cidrs" { type = list(string) }
variable "feed_egress_cidrs" { type = list(string) }

variable "domain_name" { type = string }
variable "route53_zone_id" {
  type    = string
  default = null
}
variable "certificate_arn" {
  type    = string
  default = null
}

variable "image" {
  description = "Full image reference, repository_url:tag"
  type        = string
}
variable "ecr_repository_arn" { type = string }
variable "task_cpu" { type = number }
variable "task_memory" { type = number }
variable "desired_count" { type = number }
variable "min_count" { type = number }
variable "max_count" { type = number }
variable "ingest_schedule" { type = string }

variable "db_host" { type = string }
variable "db_port" { type = number }
variable "db_name" { type = string }
variable "db_security_group_id" { type = string }
variable "db_master_secret_arn" { type = string }

variable "llm_model_id" { type = string }
variable "embedding_model_id" { type = string }
variable "bedrock_model_arns" { type = list(string) }
variable "guardrail_id" { type = string }
variable "guardrail_arn" { type = string }
variable "guardrail_version" { type = string }

variable "misp_url" { type = string }
variable "misp_trusted_orgs" { type = string }
variable "opencti_url" { type = string }

variable "deletion_protection" { type = bool }
