output "state_bucket" {
  description = "Use as -backend-config=bucket=... when initialising the environment stacks."
  value       = aws_s3_bucket.state.id
}

output "state_region" { value = var.aws_region }

output "plan_role_arn" {
  description = "GitHub repository variable AWS_PLAN_ROLE_ARN"
  value       = module.github_oidc.plan_role_arn
}

output "deploy_role_arns" {
  description = "GitHub environment variable AWS_DEPLOY_ROLE_ARN (one per environment)"
  value       = module.github_oidc.deploy_role_arns
}

output "ecr_repository_urls" {
  value = { for e, m in module.ecr : e => m.repository_url }
}
