variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "github_repository" {
  description = "owner/name of the GitHub repository whose workflows may deploy"
  type        = string
}

variable "environments" {
  description = "Environments deployed into this AWS account"
  type        = list(string)
  default     = ["staging", "prod"]
  validation {
    condition     = alltrue([for e in var.environments : contains(["staging", "prod"], e)])
    error_message = "environments may only contain staging and prod."
  }
}
