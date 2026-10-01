variable "github_repository" {
  description = "owner/name of the repository allowed to assume the roles"
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must look like owner/name."
  }
}
variable "environments" {
  description = "Deployment environments hosted in this AWS account"
  type        = list(string)
}
variable "region" { type = string }
variable "account_id" { type = string }
variable "state_bucket_arn" { type = string }
variable "state_kms_key_arn" { type = string }
variable "ecr_repository_arns" {
  description = "environment => ECR repository ARN"
  type        = map(string)
}
