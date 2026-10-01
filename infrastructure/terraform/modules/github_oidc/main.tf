# GitHub Actions -> AWS federation with no long-lived credentials.
#
#   gha-tirag-plan            pull_request          read-only; used for `terraform plan` on PRs
#   gha-tirag-deploy-<env>    environment:<env>     push the image + terraform apply for that env only
#
# The deploy roles can create and manage everything the stack contains, but an explicit deny keeps
# them away from the bootstrap resources (OIDC provider, these roles, the state bucket) so a
# compromised pipeline cannot widen its own permissions.

locals {
  repo = var.github_repository
  # AWS ignores the thumbprint for GitHub's OIDC provider (it validates via its trusted CA store);
  # the provider resource historically required a value, so the publicly documented one is supplied.
  github_thumbprint = "6938fd4d98bab03faadb97b34396831e3780aea1"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [local.github_thumbprint]
}

# ---- plan role -----------------------------------------------------------------------------------
data "aws_iam_policy_document" "plan_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.repo}:pull_request"]
    }
  }
}

resource "aws_iam_role" "plan" {
  name                 = "gha-tirag-plan"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "plan_state" {
  statement {
    sid       = "ReadState"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [var.state_bucket_arn, "${var.state_bucket_arn}/*"]
  }
  statement {
    sid       = "DecryptState"
    actions   = ["kms:Decrypt"]
    resources = [var.state_kms_key_arn]
  }
}

resource "aws_iam_role_policy" "plan_state" {
  name   = "read-state"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_state.json
}

# ---- deploy roles --------------------------------------------------------------------------------
data "aws_iam_policy_document" "deploy_trust" {
  for_each = toset(var.environments)
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # `environment:<env>` is only issued to jobs that passed that GitHub environment's protection
    # rules (required reviewers / branch restrictions).
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${local.repo}:environment:${each.key}"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  for_each             = toset(var.environments)
  name                 = "gha-tirag-deploy-${each.key}"
  assume_role_policy   = data.aws_iam_policy_document.deploy_trust[each.key].json
  max_session_duration = 3600
}

# 1) state, image registry
data "aws_iam_policy_document" "deploy_state_registry" {
  for_each = toset(var.environments)

  statement {
    sid       = "StateObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${var.state_bucket_arn}/tirag/${each.key}/*"]
  }
  statement {
    sid       = "StateList"
    actions   = ["s3:ListBucket"]
    resources = [var.state_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["tirag/${each.key}/*"]
    }
  }
  statement {
    sid       = "StateKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.state_kms_key_arn]
  }
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "EcrPushPull"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:CompleteLayerUpload",
      "ecr:DescribeImages", "ecr:DescribeRepositories", "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart", "ecr:ListTagsForResource",
    ]
    resources = [var.ecr_repository_arns[each.key]]
  }
}

# 2) compute / network / data services created by the stack
data "aws_iam_policy_document" "deploy_infra" {
  #checkov:skip=CKV_AWS_109: deploy role must create the stack; see docs/security.md "Known limitations" - mitigated by environment approval, explicit deny on bootstrap IAM, and short sessions
  #checkov:skip=CKV_AWS_111: same as CKV_AWS_109
  #checkov:skip=CKV_AWS_356: most create-time EC2/RDS/ECS actions do not support resource-level permissions
  statement {
    sid = "Network"
    actions = [
      "ec2:*Vpc*", "ec2:*Subnet*", "ec2:*RouteTable*", "ec2:*Route", "ec2:*InternetGateway*",
      "ec2:*NatGateway*", "ec2:*Address*", "ec2:*SecurityGroup*", "ec2:*NetworkAcl*", "ec2:*FlowLogs",
      "ec2:CreateFlowLogs", "ec2:DeleteFlowLogs", "ec2:CreateTags", "ec2:DeleteTags", "ec2:Describe*",
      "ec2:ModifyVpcEndpoint", "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "Database"
    actions   = ["rds:*"]
    resources = ["*"]
  }
  statement {
    sid       = "Containers"
    actions   = ["ecs:*", "application-autoscaling:*", "scheduler:*"]
    resources = ["*"]
  }
  statement {
    sid       = "LoadBalancing"
    actions   = ["elasticloadbalancing:*", "wafv2:*"]
    resources = ["*"]
  }
  statement {
    sid       = "Observability"
    actions   = ["logs:*", "cloudwatch:*", "sns:*"]
    resources = ["*"]
  }
}

# 3) security, storage, DNS and AI services created by the stack
data "aws_iam_policy_document" "deploy_platform" {
  #checkov:skip=CKV_AWS_109: deploy role must create the stack; see docs/security.md "Known limitations"
  #checkov:skip=CKV_AWS_111: same as CKV_AWS_109
  #checkov:skip=CKV_AWS_356: KMS/ACM/Route 53/Backup create-time actions do not support resource-level permissions
  statement {
    sid       = "Keys"
    actions   = ["kms:*"]
    resources = ["*"]
  }
  statement {
    sid       = "Secrets"
    actions   = ["secretsmanager:*"]
    resources = ["arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:tirag-*"]
  }
  statement {
    sid       = "SecretsList"
    actions   = ["secretsmanager:ListSecrets", "secretsmanager:GetRandomPassword"]
    resources = ["*"]
  }
  statement {
    sid       = "Backup"
    actions   = ["backup:*", "backup-storage:*"]
    resources = ["*"]
  }
  statement {
    sid       = "Certificates"
    actions   = ["acm:*"]
    resources = ["*"]
  }
  statement {
    sid       = "Dns"
    actions   = ["route53:*"]
    resources = ["*"]
  }
  statement {
    sid       = "Guardrails"
    actions   = ["bedrock:CreateGuardrail*", "bedrock:UpdateGuardrail", "bedrock:DeleteGuardrail", "bedrock:GetGuardrail", "bedrock:ListGuardrails", "bedrock:ListTagsForResource", "bedrock:TagResource", "bedrock:UntagResource"]
    resources = ["*"]
  }
  statement {
    sid       = "AlbLogBucket"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::tirag-*-alb-logs-${var.account_id}", "arn:aws:s3:::tirag-*-alb-logs-${var.account_id}/*"]
  }
  statement {
    sid       = "ReadAccount"
    actions   = ["sts:GetCallerIdentity", "elasticloadbalancing:DescribeAccountLimits"]
    resources = ["*"]
  }
}

# 4) IAM: only roles named for this environment, only the managed policies the stack attaches
data "aws_iam_policy_document" "deploy_iam" {
  for_each = toset(var.environments)

  statement {
    sid = "ManageEnvironmentRoles"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:UpdateAssumeRolePolicy",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy", "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole", "iam:TagRole",
      "iam:UntagRole", "iam:UpdateRole", "iam:PassRole",
    ]
    resources = ["arn:aws:iam::${var.account_id}:role/tirag-${each.key}-*"]
  }
  statement {
    sid       = "AttachOnlyKnownManagedPolicies"
    actions   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
    resources = ["arn:aws:iam::${var.account_id}:role/tirag-${each.key}-*"]
    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values = [
        "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole",
        "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
      ]
    }
  }
  statement {
    sid       = "ServiceLinkedRoles"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "ecs.amazonaws.com", "ecs.application-autoscaling.amazonaws.com", "elasticloadbalancing.amazonaws.com",
        "rds.amazonaws.com", "wafv2.amazonaws.com", "backup.amazonaws.com", "autoscaling.amazonaws.com",
      ]
    }
  }
  statement {
    sid       = "ReadIam"
    actions   = ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"]
    resources = ["arn:aws:iam::aws:policy/*"]
  }
  # Guard-rail: the pipeline must never be able to edit its own identity or the bootstrap resources.
  statement {
    sid     = "DenyBootstrapTampering"
    effect  = "Deny"
    actions = ["iam:*"]
    resources = [
      "arn:aws:iam::${var.account_id}:role/gha-tirag-*",
      "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com",
    ]
  }
  statement {
    sid       = "DenyStateBucketTampering"
    effect    = "Deny"
    actions   = ["s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration"]
    resources = [var.state_bucket_arn]
  }
}

locals {
  deploy_policies = merge(
    { for e in var.environments : "${e}-state-registry" => { env = e, doc = data.aws_iam_policy_document.deploy_state_registry[e].json } },
    { for e in var.environments : "${e}-infra" => { env = e, doc = data.aws_iam_policy_document.deploy_infra.json } },
    { for e in var.environments : "${e}-platform" => { env = e, doc = data.aws_iam_policy_document.deploy_platform.json } },
    { for e in var.environments : "${e}-iam" => { env = e, doc = data.aws_iam_policy_document.deploy_iam[e].json } },
  )
}

resource "aws_iam_policy" "deploy" {
  for_each = local.deploy_policies
  name     = "gha-tirag-deploy-${each.key}"
  policy   = each.value.doc
}

resource "aws_iam_role_policy_attachment" "deploy" {
  for_each   = local.deploy_policies
  role       = aws_iam_role.deploy[each.value.env].name
  policy_arn = aws_iam_policy.deploy[each.key].arn
}
