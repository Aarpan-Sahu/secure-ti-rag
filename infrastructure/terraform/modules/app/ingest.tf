# One-off db-init task (schema + pgvector extension) and the scheduled feed-ingest task.
# Run db-init once after the first apply:
#   aws ecs run-task --cluster <cluster> --task-definition <db_init_task_definition> --launch-type FARGATE ...

resource "aws_ecs_task_definition" "db_init" {
  family                   = "${var.name}-db-init"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.ingest.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([merge(local.hardening, {
    name        = "db-init"
    image       = var.image
    essential   = true
    command     = ["db-init"]
    environment = [for k, v in local.base_env : { name = k, value = v }]
    secrets     = local.db_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.dbinit.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "db-init"
      }
    }
  })])
}

resource "aws_ecs_task_definition" "ingest" {
  count                    = local.ingest_sources == "" ? 0 : 1
  family                   = "${var.name}-ingest"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.ingest.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([merge(local.hardening, {
    name        = "ingest"
    image       = var.image
    essential   = true
    command     = ["ingest", "--source", local.ingest_sources]
    environment = [for k, v in merge(local.base_env, local.feed_env) : { name = k, value = v }]
    secrets     = local.ingest_secrets
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.ingest.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "ingest"
      }
    }
  })])
}

locals {
  schedule_enabled = local.ingest_sources != "" && var.ingest_schedule != ""
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  count              = local.schedule_enabled ? 1 : 0
  name               = "${var.name}-ingest-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

data "aws_iam_policy_document" "scheduler" {
  count = local.schedule_enabled ? 1 : 0
  statement {
    actions   = ["ecs:RunTask"]
    resources = [aws_ecs_task_definition.ingest[0].arn]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.this.arn]
    }
  }
  statement {
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.execution.arn, aws_iam_role.ingest.arn]
    condition {
      test     = "StringLike"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "scheduler" {
  count  = local.schedule_enabled ? 1 : 0
  name   = "run-ingest-task"
  role   = aws_iam_role.scheduler[0].id
  policy = data.aws_iam_policy_document.scheduler[0].json
}

resource "aws_scheduler_schedule" "ingest" {
  #checkov:skip=CKV_AWS_297: schedule payload contains only a task-definition ARN and subnet ids, no sensitive data; unverifiable CMK grant requirements judged not worth the risk of a silent scheduling failure
  count               = local.schedule_enabled ? 1 : 0
  name                = "${var.name}-ingest"
  schedule_expression = var.ingest_schedule
  state               = "ENABLED"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_ecs_cluster.this.arn
    role_arn = aws_iam_role.scheduler[0].arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.ingest[0].arn
      launch_type         = "FARGATE"
      task_count          = 1
      network_configuration {
        subnets          = var.app_subnet_ids
        security_groups  = [aws_security_group.ingest.id]
        assign_public_ip = false
      }
    }

    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = 3600
    }
  }
}
