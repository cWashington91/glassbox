# Private-subnet-only VPC: no Internet Gateway, no NAT Gateway. That
# absence is the actual enforcement mechanism for "no outbound internet
# from the analyzer" -- there is simply no route to 0.0.0.0/0 for the
# Lambda's ENI to use. The only thing punched through is S3, via a
# Gateway endpoint (free -- no hourly charge, unlike Interface
# endpoints), scoped to just this bucket.
#
# CloudWatch Logs still works without a Logs endpoint or NAT: Lambda
# captures stdout/stderr and ships it to CloudWatch through its own
# internal mechanism, not through the function's VPC-attached network
# path. That's only bypassed if code makes its own explicit CloudWatch
# Logs API calls, which handler.py doesn't -- it just uses `logging`.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "analyzer" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-analyzer"
  }
}

resource "aws_subnet" "private" {
  count = 2

  vpc_id            = aws_vpc.analyzer.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project_name}-analyzer-private-${count.index}"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.analyzer.id

  # Deliberately no aws_route to an Internet Gateway or NAT Gateway here.
  # Local (intra-VPC) routing is implicit; S3 reachability comes from the
  # gateway endpoint association below, not a route to the internet.

  tags = {
    Name = "${var.project_name}-analyzer-private"
  }
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${var.aws_region}.s3"
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.analyzer.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  # Endpoint policy is a second, independent layer on top of the Lambda's
  # own IAM policy -- even a broader-than-intended role couldn't use this
  # endpoint to reach any bucket other than this one.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = ["${aws_s3_bucket.analysis.arn}/*"]
      }
    ]
  })
}

resource "aws_security_group" "lambda" {
  name        = "${var.project_name}-ghidra-analyzer"
  description = "Egress restricted to the S3 prefix list only"
  vpc_id      = aws_vpc.analyzer.id

  egress {
    description     = "HTTPS to S3 (via the gateway endpoint)"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.s3.id]
  }
}
