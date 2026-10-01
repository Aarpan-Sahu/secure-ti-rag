# Non-secret staging settings. Account ids, hostnames and CIDRs below are placeholders (RFC 5737 /
# example.org); replace them with real values in a private tfvars override or CI variables.
environment = "staging"
aws_region  = "us-east-1"

domain_name       = "tirag-staging.example.org"
alb_ingress_cidrs = ["198.51.100.0/24"] # corporate VPN egress range (placeholder)

desired_count     = 1
min_count         = 1
max_count         = 3
nat_gateway_count = 1

db_instance_class        = "db.t4g.small"
db_multi_az              = false
db_allocated_storage     = 20
db_max_allocated_storage = 100
db_backup_retention_days = 7
db_deletion_protection   = false

ingest_schedule    = "rate(6 hours)"
log_retention_days = 30


# misp_url / opencti_url / feed_egress_cidrs: set when the feeds exist, e.g.
# misp_url          = "https://misp.example.org"
# feed_egress_cidrs = ["203.0.113.10/32"]
