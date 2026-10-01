# Non-secret production settings. Placeholders as in staging.tfvars.
environment = "prod"
aws_region  = "us-east-1"

domain_name       = "tirag.example.org"
alb_ingress_cidrs = ["198.51.100.0/24"] # corporate VPN egress range (placeholder)

desired_count     = 2
min_count         = 2
max_count         = 6
nat_gateway_count = 2 # one per AZ: egress survives an AZ failure

db_instance_class        = "db.t4g.medium"
db_multi_az              = true
db_allocated_storage     = 50
db_max_allocated_storage = 200
db_backup_retention_days = 14
db_deletion_protection   = true

ingest_schedule    = "rate(1 hour)"
log_retention_days = 365
