locals {
  ai_triage_function_name = "${var.project_name}-ai-triage"
}

# Stage 2 is a plain ZIP deployment, not a container image: it's just
# boto3 (already bundled in every Lambda Python runtime) plus three
# small files. No JVM, no multi-GB image, no ECR repo needed at all --
# a real structural simplification compared to Stage 1, not just a
# smaller version of the same pattern.
data "archive_file" "ai_triage" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/ai-triage"
  output_path = "${path.module}/build/ai-triage.zip"
  excludes    = ["test_handler_local.py"]
}

resource "aws_cloudwatch_log_group" "ai_triage" {
  name              = "/aws/lambda/${local.ai_triage_function_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "ai_triage" {
  name               = local.ai_triage_function_name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "ai_triage" {
  statement {
    sid       = "ReadReports"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.analysis.arn}/reports/*"]
  }

  statement {
    sid       = "WriteTriageResults"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.analysis.arn}/triage/*"]
  }

  # Scoped to this specific model, covering both possible Bedrock
  # invocation shapes -- a direct foundation-model ARN, and a
  # cross-region inference-profile ARN. Which one actually applies
  # depends on how this model is served in this account/region; the
  # inference-profile branch is deliberately wildcarded wider since
  # profile ID naming isn't something to guess confidently here.
  statement {
    sid     = "InvokeTriageModel"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:${var.aws_region}::foundation-model/${var.bedrock_model_id}",
      "arn:aws:bedrock:${var.aws_region}:${data.aws_caller_identity.current.account_id}:inference-profile/*",
    ]
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.ai_triage.arn}:*"]
  }
}

resource "aws_iam_role_policy" "ai_triage" {
  name   = local.ai_triage_function_name
  role   = aws_iam_role.ai_triage.id
  policy = data.aws_iam_policy_document.ai_triage.json
}

resource "aws_lambda_function" "ai_triage" {
  function_name = local.ai_triage_function_name
  role          = aws_iam_role.ai_triage.arn

  filename         = data.archive_file.ai_triage.output_path
  source_code_hash = data.archive_file.ai_triage.output_base64sha256
  handler          = "handler.lambda_handler"
  runtime          = "python3.13"
  architectures    = ["x86_64"]

  timeout     = var.ai_triage_timeout_seconds
  memory_size = var.ai_triage_memory_mb

  environment {
    variables = {
      BEDROCK_MODEL_ID = var.bedrock_model_id
    }
  }

  # Deliberately NOT VPC-attached, unlike the Ghidra analyzer. Bedrock
  # has no free Gateway endpoint (only paid Interface endpoints, same
  # cost profile as the CloudWatch Logs endpoint skipped earlier), and
  # this function's risk profile is genuinely different from Stage 1's:
  # it processes Stage 1's own structured JSON output, not raw
  # attacker-controlled bytes through a native binary parser. Paying for
  # network isolation here would buy little real risk reduction.

  depends_on = [aws_cloudwatch_log_group.ai_triage]
}

resource "aws_lambda_permission" "allow_s3_invoke_triage" {
  statement_id  = "AllowS3InvokeTriage"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ai_triage.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.analysis.arn
}
