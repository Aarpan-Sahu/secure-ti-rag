# Managed Bedrock Guardrail applied by the application to every model call (defence in depth on top
# of the application-level injection and output guardrails). The prompt-attack filter is on input only
# (AWS does not support an output strength for it).

variable "name" { type = string }
variable "kms_key_arn" { type = string }

resource "aws_bedrock_guardrail" "this" {
  name                      = var.name
  description               = "Threat-intel RAG: block prompt attacks and harmful content; mask credentials in output"
  blocked_input_messaging   = "The request was blocked by the content policy."
  blocked_outputs_messaging = "The response was withheld by the content policy."
  kms_key_arn               = var.kms_key_arn

  content_policy_config {
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
    filters_config {
      type            = "HATE"
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
    }
    filters_config {
      type            = "INSULTS"
      input_strength  = "MEDIUM"
      output_strength = "MEDIUM"
    }
  }

  # Threat intelligence legitimately discusses IPs, domains and URLs, so those entity types are NOT
  # filtered. Only credential-shaped material is masked in answers.
  sensitive_information_policy_config {
    pii_entities_config {
      type   = "AWS_ACCESS_KEY"
      action = "ANONYMIZE"
    }
    pii_entities_config {
      type   = "AWS_SECRET_KEY"
      action = "ANONYMIZE"
    }
    pii_entities_config {
      type   = "PASSWORD"
      action = "ANONYMIZE"
    }
  }
}

resource "aws_bedrock_guardrail_version" "this" {
  guardrail_arn = aws_bedrock_guardrail.this.guardrail_arn
  description   = "Managed by Terraform"

  lifecycle {
    create_before_destroy = true
  }
}

output "guardrail_id" { value = aws_bedrock_guardrail.this.guardrail_id }
output "guardrail_arn" { value = aws_bedrock_guardrail.this.guardrail_arn }
output "guardrail_version" { value = aws_bedrock_guardrail_version.this.version }
