data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

locals {
  embedding_model_arn = "arn:aws:bedrock:${var.region}::foundation-model/${var.embedding_model_id}"

  runtime_secret_arns = concat(
    [aws_secretsmanager_secret.api_keys.arn, var.db_master_secret_arn],
    aws_secretsmanager_secret.misp[*].arn,
    aws_secretsmanager_secret.opencti[*].arn,
  )
}

# --- execution role: what ECS itself needs to start a task (pull image, write logs, fetch secrets) ---
resource "aws_iam_role" "execution" {
  name               = "${var.name}-ecs-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "EcrPull"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = [var.ecr_repository_arn]
  }
  statement {
    sid     = "Logs"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "${aws_cloudwatch_log_group.api.arn}:*",
      "${aws_cloudwatch_log_group.ingest.arn}:*",
      "${aws_cloudwatch_log_group.dbinit.arn}:*",
    ]
  }
  statement {
    sid       = "Secrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.runtime_secret_arns
  }
  statement {
    sid       = "DecryptSecrets"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "start-tasks"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# --- API task role: Bedrock for the configured models and the guardrail, nothing else -----------------
resource "aws_iam_role" "api" {
  name               = "${var.name}-api-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "api" {
  statement {
    sid     = "InvokeConfiguredModels"
    actions = ["bedrock:InvokeModel", "bedrock:Converse"]
    resources = concat(
      var.bedrock_model_arns,
      [local.embedding_model_arn],
    )
  }
  statement {
    sid       = "ApplyGuardrail"
    actions   = ["bedrock:ApplyGuardrail"]
    resources = [var.guardrail_arn]
  }
}

resource "aws_iam_role_policy" "api" {
  name   = "bedrock-invoke"
  role   = aws_iam_role.api.id
  policy = data.aws_iam_policy_document.api.json
}

# --- ingest task role: embeddings only (it never calls the answer model) -----------------------------
resource "aws_iam_role" "ingest" {
  name               = "${var.name}-ingest-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "ingest" {
  statement {
    sid       = "InvokeEmbeddingModel"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.embedding_model_arn]
  }
}

resource "aws_iam_role_policy" "ingest" {
  name   = "bedrock-embed"
  role   = aws_iam_role.ingest.id
  policy = data.aws_iam_policy_document.ingest.json
}
