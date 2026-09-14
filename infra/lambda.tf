resource "aws_lambda_function" "ghidra_analyzer" {
  function_name = local.function_name
  role          = aws_iam_role.ghidra_analyzer.arn

  package_type  = "Image"
  image_uri     = var.analyzer_image_uri
  architectures = ["x86_64"]

  timeout     = var.lambda_timeout_seconds
  memory_size = var.lambda_memory_mb

  ephemeral_storage {
    size = var.lambda_ephemeral_storage_mb
  }

  # Private-subnet-only VPC (see network.tf): no route to the internet
  # exists at all, so "no outbound internet from the analyzer" is
  # enforced by network topology, not just code discipline. S3 stays
  # reachable via the free gateway endpoint.
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  depends_on = [aws_cloudwatch_log_group.ghidra_analyzer]
}

resource "aws_lambda_permission" "allow_s3_invoke" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ghidra_analyzer.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.analysis.arn
}
