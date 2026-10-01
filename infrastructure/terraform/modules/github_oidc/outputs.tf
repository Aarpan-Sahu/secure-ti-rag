output "plan_role_arn" { value = aws_iam_role.plan.arn }
output "deploy_role_arns" {
  value = { for e, r in aws_iam_role.deploy : e => r.arn }
}
output "oidc_provider_arn" { value = aws_iam_openid_connect_provider.github.arn }
