resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

locals {
  base_env = {
    TIRAG_ENV                       = var.environment
    TIRAG_LOG_LEVEL                 = "INFO"
    TIRAG_STORE_BACKEND             = "pgvector"
    TIRAG_DB_HOST                   = var.db_host
    TIRAG_DB_PORT                   = tostring(var.db_port)
    TIRAG_DB_NAME                   = var.db_name
    TIRAG_DB_SSLMODE                = "verify-full"
    TIRAG_DB_SSLROOTCERT            = "/etc/ssl/rds/global-bundle.pem"
    TIRAG_AUTO_MIGRATE              = "false"
    TIRAG_AUTH_MODE                 = "apikey"
    TIRAG_ENABLE_DOCS               = "false"
    TIRAG_EMBEDDING_PROVIDER        = "bedrock"
    TIRAG_EMBEDDING_DIM             = "1024"
    TIRAG_EMBEDDING_MODEL_ID        = var.embedding_model_id
    TIRAG_LLM_PROVIDER              = "bedrock"
    TIRAG_LLM_MODEL_ID              = var.llm_model_id
    TIRAG_AWS_REGION                = var.region
    TIRAG_BEDROCK_GUARDRAIL_ID      = var.guardrail_id
    TIRAG_BEDROCK_GUARDRAIL_VERSION = var.guardrail_version
  }

  feed_env = merge(
    var.misp_url == "" ? {} : {
      TIRAG_MISP_URL          = var.misp_url
      TIRAG_MISP_TRUSTED_ORGS = var.misp_trusted_orgs
    },
    var.opencti_url == "" ? {} : { TIRAG_OPENCTI_URL = var.opencti_url },
  )

  db_secrets = [
    { name = "TIRAG_DB_USER", valueFrom = "${var.db_master_secret_arn}:username::" },
    { name = "TIRAG_DB_PASSWORD", valueFrom = "${var.db_master_secret_arn}:password::" },
  ]

  ingest_secrets = concat(
    local.db_secrets,
    [for s in aws_secretsmanager_secret.misp : { name = "TIRAG_MISP_API_KEY", valueFrom = s.arn }],
    [for s in aws_secretsmanager_secret.opencti : { name = "TIRAG_OPENCTI_TOKEN", valueFrom = s.arn }],
  )

  ingest_sources = var.misp_url != "" && var.opencti_url != "" ? "all" : (
    var.misp_url != "" ? "misp" : (var.opencti_url != "" ? "opencti" : "")
  )

  hardening = {
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    privileged             = false
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    mountPoints = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
  }

}

# --- API ---------------------------------------------------------------------------------------------
resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.api.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([merge(local.hardening, {
    name         = "api"
    image        = var.image
    essential    = true
    stopTimeout  = 30
    portMappings = [{ containerPort = 8080, protocol = "tcp" }]
    environment  = [for k, v in local.base_env : { name = k, value = v }]
    secrets = concat(local.db_secrets, [
      { name = "TIRAG_API_KEYS_JSON", valueFrom = aws_secretsmanager_secret.api_keys.arn },
    ])
    healthCheck = {
      command     = ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 20
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.api.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "api"
      }
    }
  })])
}

resource "aws_ecs_service" "api" {
  name                               = "api"
  cluster                            = aws_ecs_cluster.this.id
  task_definition                    = aws_ecs_task_definition.api.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  platform_version                   = "LATEST"
  health_check_grace_period_seconds  = 60
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  propagate_tags                     = "SERVICE"

  # A deployment whose tasks never become healthy is rolled back automatically to the last good revision.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.app_subnet_ids
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8080
  }

  lifecycle {
    ignore_changes = [desired_count] # owned by the autoscaler
  }

  depends_on = [aws_lb_listener.https]
}

resource "aws_appautoscaling_target" "api" {
  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.api.name}"
  min_capacity       = var.min_count
  max_capacity       = var.max_count
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.api.service_namespace
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  resource_id        = aws_appautoscaling_target.api.resource_id

  target_tracking_scaling_policy_configuration {
    target_value       = 60
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

resource "aws_appautoscaling_policy" "requests" {
  name               = "${var.name}-requests"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.api.service_namespace
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  resource_id        = aws_appautoscaling_target.api.resource_id

  target_tracking_scaling_policy_configuration {
    target_value       = 300
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.this.arn_suffix}/${aws_lb_target_group.api.arn_suffix}"
    }
  }
}
