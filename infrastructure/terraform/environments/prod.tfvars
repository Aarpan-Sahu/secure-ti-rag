# Non-secret production settings.
environment = "prod"
aws_region  = "us-east-1"

# Deployment-specific values are NOT stored in the repository. They are supplied by the pipeline from
# the GitHub environment variable TIRAG_TFVARS_JSON (written to ci.auto.tfvars.json), for example:
#   {"domain_name": "tirag.example.org", "alb_ingress_cidrs": ["198.51.100.0/24"],
#    "route53_zone_id": "Z...", "misp_url": "https://misp.example.org",
#    "feed_egress_cidrs": ["203.0.113.10/32"], "alarm_email": "secops@example.org"}
# (domain_name and alb_ingress_cidrs are required; see variables.tf for the rest.)


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
