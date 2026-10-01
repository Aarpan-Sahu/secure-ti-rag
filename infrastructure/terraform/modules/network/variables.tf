variable "name" { type = string }
variable "vpc_cidr" { type = string }
variable "az_count" { type = number }
variable "nat_gateway_count" { type = number }
variable "region" { type = string }
variable "kms_key_arn" {
  description = "KMS key for the flow-log group."
  type        = string
}
variable "log_retention_days" { type = number }
