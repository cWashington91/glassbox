output "bucket_name" {
  description = "S3 bucket holding incoming binaries and analysis reports."
  value       = aws_s3_bucket.analysis.bucket
}

output "ecr_repository_url" {
  description = "Push the ghidra-analyzer image here."
  value       = aws_ecr_repository.ghidra_analyzer.repository_url
}

output "lambda_function_name" {
  value = aws_lambda_function.ghidra_analyzer.function_name
}

output "lambda_function_arn" {
  value = aws_lambda_function.ghidra_analyzer.arn
}
