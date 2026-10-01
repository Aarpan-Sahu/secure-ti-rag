output "vpc_id" { value = aws_vpc.this.id }
output "vpc_cidr" { value = aws_vpc.this.cidr_block }
output "public_subnet_ids" { value = aws_subnet.public[*].id }
output "app_subnet_ids" { value = aws_subnet.app[*].id }
output "data_subnet_ids" { value = aws_subnet.data[*].id }
output "app_subnet_cidrs" { value = aws_subnet.app[*].cidr_block }
output "endpoint_prefix_list_ids" {
  description = "Gateway endpoint prefix lists (S3) for security-group egress rules."
  value       = [aws_vpc_endpoint.s3.prefix_list_id]
}
