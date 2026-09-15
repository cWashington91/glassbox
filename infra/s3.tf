# Single bucket, prefix-scoped: binaries land under incoming/, reports
# get written under reports/. This is what keeps the S3 event
# notification (scoped to the incoming/ prefix below) from ever firing
# on the Lambda's own output -- a report written under reports/ cannot
# retrigger a trigger that only watches incoming/.
resource "aws_s3_bucket" "analysis" {
  bucket = "${var.project_name}-analysis-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "analysis" {
  bucket = aws_s3_bucket.analysis.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "analysis" {
  bucket = aws_s3_bucket.analysis.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "analysis" {
  bucket = aws_s3_bucket.analysis.id

  rule {
    id     = "expire-old-objects"
    status = "Enabled"

    filter {}

    expiration {
      days = var.report_expiration_days
    }
  }
}

# Defense in depth: reject any request to this bucket that isn't over
# TLS, regardless of what the IAM role above is separately allowed to do.
resource "aws_s3_bucket_policy" "analysis" {
  bucket = aws_s3_bucket.analysis.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.analysis.arn,
          "${aws_s3_bucket.analysis.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "analysis" {
  bucket = aws_s3_bucket.analysis.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.ghidra_analyzer.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "incoming/"
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke]
}
