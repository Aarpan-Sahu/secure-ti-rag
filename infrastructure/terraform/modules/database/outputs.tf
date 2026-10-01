output "endpoint_address" { value = aws_db_instance.this.address }
output "port" { value = aws_db_instance.this.port }
output "db_name" { value = aws_db_instance.this.db_name }
output "security_group_id" { value = aws_security_group.db.id }
output "instance_id" { value = aws_db_instance.this.identifier }
output "master_secret_arn" {
  description = "RDS-managed Secrets Manager secret holding {username,password}."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}
