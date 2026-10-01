terraform {
  required_version = ">= 1.10.0" # S3-native state locking (use_lockfile)

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.81.0, < 6.66.1"
    }
  }

  # Partial configuration: the bucket/region are supplied at `terraform init` time
  # (-backend-config=...) from the outputs of ./bootstrap, so no account ids live in the repo.
  backend "s3" {
    key          = "tirag/terraform.tfstate" # overridden per environment by the pipeline
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "tirag"
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = "secure-ti-rag"
    }
  }
}
