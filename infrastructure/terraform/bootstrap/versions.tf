# One-time, per-AWS-account stack, applied by a human administrator with their own credentials
# (NOT by the pipeline). It creates what the pipeline needs before it can run:
#   - the encrypted Terraform state bucket
#   - one ECR repository per environment hosted in this account
#   - the GitHub OIDC provider and the plan / deploy roles
#
#   cd infrastructure/terraform/bootstrap
#   terraform init && terraform apply -var github_repository=OWNER/REPO
#
# Its own state is small and is kept locally by default (see docs/deployment.md for migrating it
# into the bucket it creates).
terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.81.0, < 6.67.1"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "tirag"
      ManagedBy = "terraform"
      Stack     = "bootstrap"
    }
  }
}
