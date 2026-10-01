# Non-secret staging settings.
environment = "staging"
aws_region  = "us-east-1"

# Deployment-specific values are NOT stored in the repository. They are supplied by the pipeline from
# the GitHub environment variable TIRAG_TFVARS_JSON (written to ci.auto.tfvars.json), for example:
#   {"domain_name": "tirag.example.org", "alb_ingress_cidrs": ["198.51.100.0/24"],
#    "route53_zone_id": "Z...", "misp_url": "https://misp.example.org",
#    "feed_egress_cidrs": ["203.0.113.10/32"], "alarm_email": "secops@example.org"}
# (domain_name and alb_ingress_cidrs are required; see variables.tf for the rest.)


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
