data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ghidra_analyzer" {
  name               = local.function_name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

# Created explicitly (rather than left to auto-create on first log
# write) so retention is actually controlled, and so the Lambda's own
# policy below only needs CreateLogStream/PutLogEvents -- not
# logs:CreateLogGroup -- against this one, already-scoped group.
resource "aws_cloudwatch_log_group" "ghidra_analyzer" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "ghidra_analyzer" {
  statement {
    sid       = "ReadIncomingBinaries"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.analysis.arn}/incoming/*"]
  }

  statement {
    sid       = "WriteReports"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.analysis.arn}/reports/*"]
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.ghidra_analyzer.arn}:*"]
  }
}

resource "aws_iam_role_policy" "ghidra_analyzer" {
  name   = local.function_name
  role   = aws_iam_role.ghidra_analyzer.id
  policy = data.aws_iam_policy_document.ghidra_analyzer.json
}

# Required for any VPC-attached Lambda: permission to create/describe/
# delete the ENI it runs on. This is the AWS-managed policy scoped to
# exactly those three actions -- writing it by hand would just
# reproduce the same policy, not narrow it further.
resource "aws_iam_role_policy_attachment" "ghidra_analyzer_vpc_access" {
  role       = aws_iam_role.ghidra_analyzer.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
