data "aws_caller_identity" "current" {}

locals {
  function_name = "${var.project_name}-ghidra-analyzer"
}
