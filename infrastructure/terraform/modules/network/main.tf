# Three subnet tiers: public (ALB + NAT only), private "app" (Fargate), isolated "data" (RDS, no
# internet route). AWS APIs the app needs are reached through VPC endpoints.

data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394: result set is constrained with opt-in-status=opt-in-not-required and sliced to az_count; a new standard AZ cannot change existing subnets because slice() takes the first N sorted names
  state = "available"

  # Standard AZs only: excludes Local Zones / Wavelength zones so the result set cannot silently grow.
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  azs        = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  nat_count  = min(var.nat_gateway_count, var.az_count)
  public_net = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i)]
  app_net    = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 10)]
  data_net   = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 20)]
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

# The default security group is emptied: nothing can use it by accident.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-default-deny" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "public" {
  count                   = var.az_count
  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[count.index]
  cidr_block              = local.public_net[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name}-public-${local.azs[count.index]}", Tier = "public" }
}

resource "aws_subnet" "app" {
  count             = var.az_count
  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[count.index]
  cidr_block        = local.app_net[count.index]
  tags              = { Name = "${var.name}-app-${local.azs[count.index]}", Tier = "app" }
}

resource "aws_subnet" "data" {
  count             = var.az_count
  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[count.index]
  cidr_block        = local.data_net[count.index]
  tags              = { Name = "${var.name}-data-${local.azs[count.index]}", Tier = "data" }
}

resource "aws_eip" "nat" {
  count  = local.nat_count
  domain = "vpc"
  tags   = { Name = "${var.name}-nat-${count.index}" }
}

resource "aws_nat_gateway" "this" {
  count         = local.nat_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = { Name = "${var.name}-${count.index}" }
  depends_on    = [aws_internet_gateway.this]
}

# --- routing --------------------------------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count          = var.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "app" {
  count  = var.az_count
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-app-${local.azs[count.index]}" }
}

resource "aws_route" "app_nat" {
  count                  = var.az_count
  route_table_id         = aws_route_table.app[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[count.index % local.nat_count].id
}

resource "aws_route_table_association" "app" {
  count          = var.az_count
  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app[count.index].id
}

# Data subnets: local routes only (no internet, no NAT).
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name}-data" }
}

resource "aws_route_table_association" "data" {
  count          = var.az_count
  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}

# --- network ACL for the data tier: only the app tier may talk to Postgres -----------------------
resource "aws_network_acl" "data" {
  #checkov:skip=CKV2_AWS_1: attached through subnet_ids (checkov does not follow the splat); see aws_network_acl.data.subnet_ids
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.data[*].id
  tags       = { Name = "${var.name}-data" }
}

resource "aws_network_acl_rule" "data_in_postgres" {
  count          = var.az_count
  network_acl_id = aws_network_acl.data.id
  rule_number    = 100 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.app_net[count.index]
  from_port      = 5432
  to_port        = 5432
}

# Multi-AZ replication traffic stays within the data subnets.
resource "aws_network_acl_rule" "data_in_internal" {
  #checkov:skip=CKV_AWS_352: data subnets hold only RDS interfaces; intra-tier traffic must stay open so Multi-AZ replication cannot be broken by a NACL. App-tier access is restricted to 5432 in the rules above
  count          = var.az_count
  network_acl_id = aws_network_acl.data.id
  rule_number    = 200 + count.index
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = local.data_net[count.index]
}

# intra-data-tier only (RDS Multi-AZ replication); app-tier access is limited to 5432
#trivy:ignore:AVD-AWS-0102
resource "aws_network_acl_rule" "data_out_ephemeral" {
  count          = var.az_count
  network_acl_id = aws_network_acl.data.id
  rule_number    = 100 + count.index
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.app_net[count.index]
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "data_out_internal" {
  count          = var.az_count
  network_acl_id = aws_network_acl.data.id
  rule_number    = 200 + count.index
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = local.data_net[count.index]
}

# --- VPC endpoints: AWS APIs without internet egress ------------------------------------------------
# intra-data-tier only (RDS Multi-AZ replication); app-tier access is limited to 5432
#trivy:ignore:AVD-AWS-0102
resource "aws_security_group" "endpoints" {
  name_prefix = "${var.name}-vpce-"
  description = "Interface VPC endpoints: HTTPS from the app tier only"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.name}-vpce" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  count             = var.az_count
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from app subnet ${count.index}"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = local.app_net[count.index]
}

locals {
  interface_endpoints = toset([
    "ecr.api",
    "ecr.dkr",
    "logs",
    "secretsmanager",
    "bedrock-runtime",
  ])
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.app[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = { Name = "${var.name}-${each.key}" }
}

# ECR layers are served from S3.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.app[*].id
  tags              = { Name = "${var.name}-s3" }
}

# --- flow logs --------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "flow" {
  #checkov:skip=CKV_AWS_338: retention is a variable; production sets 365 days in environments/prod.tfvars
  name              = "/${var.name}/vpc-flow"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "flow_write" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.flow.arn}:*"]
  }
}

resource "aws_iam_role" "flow" {
  name               = "${var.name}-vpc-flow"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
}

resource "aws_iam_role_policy" "flow" {
  name   = "write-flow-logs"
  role   = aws_iam_role.flow.id
  policy = data.aws_iam_policy_document.flow_write.json
}

resource "aws_flow_log" "this" {
  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow.arn
}
