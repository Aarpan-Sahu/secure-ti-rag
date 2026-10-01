output "api_url" {
  description = "Base URL of the API (DNS must point at the ALB)."
  value       = "https://${var.domain_name}"
}

output "alb_dns_name" {
  description = "Create a CNAME/alias from the domain to this name when route53_zone_id is not used."
  value       = module.app.alb_dns_name
}

output "ecr_repository_url" { value = data.aws_ecr_repository.this.repository_url }
output "ecs_cluster" { value = module.app.cluster_name }
output "ecs_service" { value = module.app.service_name }
output "db_init_task_definition" { value = module.app.db_init_task_definition }
output "private_subnet_ids" { value = module.network.app_subnet_ids }
output "ingest_security_group_id" { value = module.app.ingest_security_group_id }
output "api_keys_secret_arn" { value = module.app.api_keys_secret_arn }
output "misp_secret_arn" { value = module.app.misp_secret_arn }
output "opencti_secret_arn" { value = module.app.opencti_secret_arn }
output "dashboard_name" { value = module.observability.dashboard_name }
output "alarm_topic_arn" { value = aws_sns_topic.alarms.arn }
output "bedrock_guardrail_id" { value = module.guardrail.guardrail_id }
