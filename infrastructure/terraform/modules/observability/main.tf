# Alarms map to the SLOs in monitoring/slo.md:
#   availability  - ALB 5xx ratio and unhealthy targets
#   latency       - target response time p95
#   freshness     - ingest task failures (feed read errors) and missing ingest runs
#   security      - auth-failure spikes, guardrail blocks, WAF blocks

locals {
  alarm_actions = [var.alarm_topic_arn]
}

# --- availability -------------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "alb_5xx_ratio" {
  alarm_name          = "${var.name}-alb-5xx-ratio"
  alarm_description   = "More than 2% of responses are 5xx over 10 minutes (availability SLO burn)"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 2
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions

  metric_query {
    id          = "ratio"
    expression  = "100 * (e5xx / MAX([requests, 1]))"
    label       = "5xx %"
    return_data = true
  }
  metric_query {
    id = "e5xx"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "HTTPCode_Target_5XX_Count"
      period      = 300
      stat        = "Sum"
      dimensions  = { LoadBalancer = var.alb_arn_suffix }
    }
  }
  metric_query {
    id = "requests"
    metric {
      namespace   = "AWS/ApplicationELB"
      metric_name = "RequestCount"
      period      = 300
      stat        = "Sum"
      dimensions  = { LoadBalancer = var.alb_arn_suffix }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  alarm_name          = "${var.name}-unhealthy-targets"
  alarm_description   = "At least one API task is failing its health check"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  dimensions          = { LoadBalancer = var.alb_arn_suffix, TargetGroup = var.target_group_arn_suffix }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "no_healthy_targets" {
  alarm_name          = "${var.name}-no-healthy-targets"
  alarm_description   = "No healthy API task behind the load balancer (outage)"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HealthyHostCount"
  dimensions          = { LoadBalancer = var.alb_arn_suffix, TargetGroup = var.target_group_arn_suffix }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# --- latency ------------------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "latency_p95" {
  alarm_name          = "${var.name}-latency-p95"
  alarm_description   = "p95 target response time above 8s for 15 minutes (query path includes an LLM call)"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "TargetResponseTime"
  dimensions          = { LoadBalancer = var.alb_arn_suffix }
  extended_statistic  = "p95"
  period              = 300
  evaluation_periods  = 3
  threshold           = 8
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# --- capacity -----------------------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "ecs_cpu" {
  alarm_name          = "${var.name}-ecs-cpu-high"
  alarm_description   = "Service CPU above 85% for 10 minutes (autoscaling may be at max)"
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  dimensions          = { ClusterName = var.cluster_name, ServiceName = var.service_name }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "ecs_memory" {
  alarm_name          = "${var.name}-ecs-memory-high"
  alarm_description   = "Service memory above 85% for 10 minutes"
  namespace           = "AWS/ECS"
  metric_name         = "MemoryUtilization"
  dimensions          = { ClusterName = var.cluster_name, ServiceName = var.service_name }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.name}-rds-cpu-high"
  alarm_description   = "Database CPU above 80% for 15 minutes"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = var.db_instance_id }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "${var.name}-rds-storage-low"
  alarm_description   = "Less than 10 GiB of free database storage"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = var.db_instance_id }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10737418240
  comparison_operator = "LessThanThreshold"
  alarm_actions       = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  alarm_name          = "${var.name}-rds-connections-high"
  alarm_description   = "Database connection count unusually high (pool leak or traffic spike)"
  namespace           = "AWS/RDS"
  metric_name         = "DatabaseConnections"
  dimensions          = { DBInstanceIdentifier = var.db_instance_id }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = local.alarm_actions
}

# --- log-derived metrics (structured JSON logs) --------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "auth_failures" {
  name           = "${var.name}-auth-failures"
  log_group_name = var.api_log_group
  pattern        = "{ $.msg = \"request\" && ($.status = 401 || $.status = 403) }"
  metric_transformation {
    name          = "AuthFailures"
    namespace     = "${var.name}/app"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "query_blocked" {
  name           = "${var.name}-query-blocked"
  log_group_name = var.api_log_group
  pattern        = "{ $.msg = \"query_blocked\" }"
  metric_transformation {
    name          = "QueriesBlocked"
    namespace     = "${var.name}/app"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "upstream_errors" {
  name           = "${var.name}-upstream-errors"
  log_group_name = var.api_log_group
  pattern        = "{ $.msg = \"query_error\" }"
  metric_transformation {
    name          = "UpstreamErrors"
    namespace     = "${var.name}/app"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "ingest_feed_errors" {
  count          = var.ingest_enabled ? 1 : 0
  name           = "${var.name}-ingest-feed-errors"
  log_group_name = var.ingest_log_group
  pattern        = "{ $.msg = \"feed read failed\" || $.msg = \"failed to ingest document\" }"
  metric_transformation {
    name          = "IngestErrors"
    namespace     = "${var.name}/app"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "ingest_quarantine" {
  count          = var.ingest_enabled ? 1 : 0
  name           = "${var.name}-ingest-quarantine"
  log_group_name = var.ingest_log_group
  pattern        = "{ $.msg = \"quarantined suspected prompt-injection content\" }"
  metric_transformation {
    name          = "IngestQuarantined"
    namespace     = "${var.name}/app"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "ingest_finished" {
  count          = var.ingest_enabled ? 1 : 0
  name           = "${var.name}-ingest-finished"
  log_group_name = var.ingest_log_group
  pattern        = "{ $.msg = \"ingest finished\" }"
  metric_transformation {
    name          = "IngestRuns"
    namespace     = "${var.name}/app"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "ingest_errors" {
  count               = var.ingest_enabled ? 1 : 0
  alarm_name          = "${var.name}-ingest-errors"
  alarm_description   = "Feed ingestion reported errors (data freshness at risk)"
  namespace           = "${var.name}/app"
  metric_name         = "IngestErrors"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  depends_on          = [aws_cloudwatch_log_metric_filter.ingest_feed_errors]
}

resource "aws_cloudwatch_metric_alarm" "ingest_stale" {
  count               = var.ingest_enabled ? 1 : 0
  alarm_name          = "${var.name}-ingest-stale"
  alarm_description   = "No completed ingest run in 6 hours (freshness SLO)"
  namespace           = "${var.name}/app"
  metric_name         = "IngestRuns"
  statistic           = "Sum"
  period              = 21600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_actions
  depends_on          = [aws_cloudwatch_log_metric_filter.ingest_finished]
}

resource "aws_cloudwatch_metric_alarm" "auth_failure_spike" {
  alarm_name          = "${var.name}-auth-failure-spike"
  alarm_description   = "More than 50 failed authentications in 5 minutes (credential stuffing / leaked-key probing)"
  namespace           = "${var.name}/app"
  metric_name         = "AuthFailures"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  depends_on          = [aws_cloudwatch_log_metric_filter.auth_failures]
}

resource "aws_cloudwatch_metric_alarm" "injection_spike" {
  alarm_name          = "${var.name}-injection-attempt-spike"
  alarm_description   = "More than 20 queries blocked by the input guardrail in 10 minutes (prompt-injection campaign)"
  namespace           = "${var.name}/app"
  metric_name         = "QueriesBlocked"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  depends_on          = [aws_cloudwatch_log_metric_filter.query_blocked]
}

resource "aws_cloudwatch_metric_alarm" "waf_blocks" {
  alarm_name          = "${var.name}-waf-block-spike"
  alarm_description   = "WAF blocked more than 500 requests in 5 minutes"
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  dimensions          = { WebACL = var.web_acl_name, Region = var.region, Rule = "ALL" }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 500
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
}

# --- dashboard ----------------------------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = var.name
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6
        properties = {
          title  = "Requests and 5xx"
          region = var.region
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_arn_suffix],
            [".", "HTTPCode_Target_5XX_Count", ".", "."],
            [".", "HTTPCode_Target_4XX_Count", ".", "."],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6
        properties = {
          title  = "Target response time (p50 / p95 / p99)"
          region = var.region
          period = 300
          metrics = [
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.alb_arn_suffix, { stat = "p50" }],
            ["...", { stat = "p95" }],
            ["...", { stat = "p99" }],
          ]
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 12, height = 6
        properties = {
          title  = "ECS CPU / memory"
          region = var.region
          stat   = "Average"
          period = 300
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", var.cluster_name, "ServiceName", var.service_name],
            [".", "MemoryUtilization", ".", ".", ".", "."],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 6, width = 12, height = 6
        properties = {
          title  = "RDS CPU / connections"
          region = var.region
          stat   = "Average"
          period = 300
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", var.db_instance_id],
            [".", "DatabaseConnections", ".", "."],
          ]
        }
      },
      {
        type = "metric", x = 0, y = 12, width = 12, height = 6
        properties = {
          title  = "Security signals"
          region = var.region
          stat   = "Sum"
          period = 300
          metrics = [
            ["${var.name}/app", "AuthFailures"],
            [".", "QueriesBlocked"],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", var.web_acl_name, "Region", var.region, "Rule", "ALL"],
          ]
        }
      },
      {
        type = "log", x = 12, y = 12, width = 12, height = 6
        properties = {
          title  = "Recent errors"
          region = var.region
          query  = "SOURCE '${var.api_log_group}' | fields @timestamp, msg, request_id | filter level = 'ERROR' | sort @timestamp desc | limit 50"
        }
      },
    ]
  })
}
