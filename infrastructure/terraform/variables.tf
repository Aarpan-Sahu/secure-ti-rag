variable "aws_region" {
  description = "Region for all resources (Bedrock model availability differs by region)."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  validation {
    condition     = contains(["staging", "prod"], var.environment)
    error_message = "environment must be staging or prod."
  }
}

# ---- image ---------------------------------------------------------------------------------
variable "image_tag" {
  description = "Immutable image tag (git SHA) to run. Rolling back = applying the previous tag."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,128}$", var.image_tag)) && var.image_tag != "latest"
    error_message = "image_tag must be an immutable tag, not 'latest'."
  }
}

# ---- network -------------------------------------------------------------------------------
variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones (2 or 3)."
  type        = number
  default     = 2
  validation {
    condition     = var.az_count >= 2 && var.az_count <= 3
    error_message = "az_count must be 2 or 3."
  }
}

variable "nat_gateway_count" {
  description = "1 = single shared NAT (cheaper, AZ-dependent egress); az_count = one per AZ."
  type        = number
  default     = 1
}

variable "feed_egress_cidrs" {
  description = "CIDR blocks of the MISP / OpenCTI servers the ingest task may reach on 443. Empty = ingest has no feed egress."
  type        = list(string)
  default     = []
}

variable "alb_ingress_cidrs" {
  description = "CIDRs allowed to reach the HTTPS listener. Restrict to your corporate/VPN ranges where possible."
  type        = list(string)
  default     = []
  validation {
    condition     = !contains(var.alb_ingress_cidrs, "0.0.0.0/0") || var.allow_public_internet
    error_message = "0.0.0.0/0 requires allow_public_internet = true (explicit opt-in)."
  }
}

variable "allow_public_internet" {
  description = "Explicit opt-in to expose the ALB to the whole internet."
  type        = bool
  default     = false
}

# ---- DNS / TLS -----------------------------------------------------------------------------
variable "domain_name" {
  description = "Fully-qualified API host name, e.g. tirag.example.org (you must own it)."
  type        = string
}

variable "route53_zone_id" {
  description = "Hosted zone for domain_name. If set, Terraform creates + DNS-validates the ACM certificate and the alias record."
  type        = string
  default     = null
}

variable "certificate_arn" {
  description = "Existing ACM certificate ARN. Required when route53_zone_id is null."
  type        = string
  default     = null
  validation {
    condition     = var.certificate_arn == null || can(regex("^arn:aws:acm:", var.certificate_arn))
    error_message = "certificate_arn must be an ACM certificate ARN."
  }
}

# ---- compute -------------------------------------------------------------------------------
variable "task_cpu" {
  type    = number
  default = 512
}

variable "task_memory" {
  type    = number
  default = 1024
}

variable "desired_count" {
  type    = number
  default = 2
}

variable "min_count" {
  type    = number
  default = 2
}

variable "max_count" {
  type    = number
  default = 6
}

variable "ingest_schedule" {
  description = "EventBridge Scheduler expression for feed ingestion; empty disables the schedule."
  type        = string
  default     = "rate(1 hour)"
}

# ---- database ------------------------------------------------------------------------------
variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_allocated_storage" {
  type    = number
  default = 50
}

variable "db_max_allocated_storage" {
  type    = number
  default = 200
}

variable "db_multi_az" {
  type    = bool
  default = true
}

variable "db_backup_retention_days" {
  type    = number
  default = 14
}

variable "db_deletion_protection" {
  type    = bool
  default = true
}

# ---- AI ------------------------------------------------------------------------------------
variable "llm_model_id" {
  description = "Bedrock model or inference-profile id used for answers."
  type        = string
  default     = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
}

variable "embedding_model_id" {
  type    = string
  default = "amazon.titan-embed-text-v2:0"
}

variable "llm_foundation_model_id" {
  description = "Foundation model behind llm_model_id (the cross-region inference profile routes to it)."
  type        = string
  default     = "anthropic.claude-sonnet-4-5-20250929-v1:0"
}

variable "bedrock_inference_regions" {
  description = "Regions the cross-region inference profile may route to; the task role is allowed the foundation model in each."
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}

# ---- feeds ---------------------------------------------------------------------------------
variable "misp_url" {
  type    = string
  default = ""
}

variable "misp_trusted_orgs" {
  description = "Comma separated MISP creator-org allow-list (poisoning control)."
  type        = string
  default     = ""
}

variable "opencti_url" {
  type    = string
  default = ""
}

# ---- operations ----------------------------------------------------------------------------
variable "alarm_email" {
  description = "Email subscribed to the alarm topic (needs manual confirmation). Empty = topic only."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  type    = number
  default = 90
}
