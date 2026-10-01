# Layered, least-privilege network paths:
#   internet --443--> ALB --8080--> API tasks --5432--> RDS
#                                   API tasks --443--> VPC endpoints / S3 only
#   EventBridge Scheduler -> ingest task --443--> VPC endpoints + the feed CIDRs --5432--> RDS

resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Public ALB: HTTPS from allow-listed CIDRs only"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-alb" }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each          = toset(var.alb_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from ${each.value}"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "alb_http_redirect" {
  for_each          = toset(var.alb_ingress_cidrs)
  security_group_id = aws_security_group.alb.id
  description       = "HTTP (redirected to HTTPS) from ${each.value}"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "alb_to_tasks" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To API tasks"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.api.id
}

resource "aws_security_group" "api" {
  name_prefix = "${var.name}-api-"
  description = "API tasks: ingress only from the ALB; egress only to VPC endpoints, S3 and RDS"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-api" }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "api_from_alb" {
  security_group_id            = aws_security_group.api.id
  description                  = "From the load balancer"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "api_https_vpc" {
  security_group_id = aws_security_group.api.id
  description       = "HTTPS to interface VPC endpoints (ECR, Logs, Secrets Manager, Bedrock)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "api_https_s3" {
  for_each          = toset(var.s3_prefix_list_ids)
  security_group_id = aws_security_group.api.id
  description       = "HTTPS to S3 gateway endpoint (ECR layers)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = each.value
}

resource "aws_vpc_security_group_egress_rule" "api_to_db" {
  security_group_id            = aws_security_group.api.id
  description                  = "PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = var.db_security_group_id
}

resource "aws_security_group" "ingest" {
  #checkov:skip=CKV2_AWS_5: attached at run time by the scheduled ECS task / db-init task network configuration
  name_prefix = "${var.name}-ingest-"
  description = "Ingest / db-init tasks: no ingress; egress to endpoints, S3, RDS and the feed servers"
  vpc_id      = var.vpc_id
  tags        = { Name = "${var.name}-ingest" }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_egress_rule" "ingest_https_vpc" {
  security_group_id = aws_security_group.ingest.id
  description       = "HTTPS to interface VPC endpoints"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "ingest_https_s3" {
  for_each          = toset(var.s3_prefix_list_ids)
  security_group_id = aws_security_group.ingest.id
  description       = "HTTPS to S3 gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = each.value
}

resource "aws_vpc_security_group_egress_rule" "ingest_feeds" {
  for_each          = toset(var.feed_egress_cidrs)
  security_group_id = aws_security_group.ingest.id
  description       = "HTTPS to threat-intel feed server ${each.value}"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "ingest_to_db" {
  security_group_id            = aws_security_group.ingest.id
  description                  = "PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = var.db_security_group_id
}

# RDS only accepts connections from the two client security groups.
resource "aws_vpc_security_group_ingress_rule" "db_from_api" {
  security_group_id            = var.db_security_group_id
  description                  = "From API tasks"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.api.id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_ingest" {
  security_group_id            = var.db_security_group_id
  description                  = "From ingest / db-init tasks"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.ingest.id
}
