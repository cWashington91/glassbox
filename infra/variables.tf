variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix applied to all resources."
  type        = string
  default     = "glassbox"
}

variable "analyzer_image_uri" {
  description = <<-EOT
    Full ECR image URI (including tag or digest) for the ghidra-analyzer
    Lambda. There's an unavoidable bootstrapping order here: the ECR repo
    has to exist and already contain a pushed image before this variable
    can point at anything real. First-time deploy is two steps:
      1. tofu apply -target=aws_ecr_repository.ghidra_analyzer
      2. docker build/tag/push the image, then tofu apply with the real URI.
  EOT
  type        = string
}

variable "lambda_timeout_seconds" {
  description = "Lambda timeout for the ghidra-analyzer function. This is also the hard ceiling handler.py's remaining-time-based budgets are computed against."
  type        = number
  default     = 600
}

variable "lambda_memory_mb" {
  description = "Lambda memory for the ghidra-analyzer function. Lambda allocates vCPU proportionally to memory (~1 vCPU per 1769MB), and Ghidra's JVM is CPU-bound, so this is as much a speed dial as a RAM one -- a real test run took 112s at 2048MB (~1.16 vCPU) with only 865MB actually used, suggesting CPU share was the bottleneck, not memory headroom. 3008MB (~1.7 vCPU) is the next data point to test."
  type        = number
  default     = 3008
}

variable "lambda_ephemeral_storage_mb" {
  description = "/tmp size for the ghidra-analyzer function (the downloaded binary plus whatever scratch space Ghidra itself uses)."
  type        = number
  default     = 1024
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the ghidra-analyzer function."
  type        = number
  default     = 14
}

variable "report_expiration_days" {
  description = "Days before S3 auto-expires incoming binaries and reports, so a demo/portfolio bucket doesn't accumulate indefinitely."
  type        = number
  default     = 30
}
