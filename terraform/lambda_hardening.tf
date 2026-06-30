# terraform/lambda_hardening.tf
# GAP-05 support: network plumbing so the Lambda can run inside the VPC.
# HIPAA 164.312(e)(1) — Transmission security.

# Egress-only security group for the Lambda's ENIs in the private subnets.
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-${local.suffix}"
  description = "Egress-only SG for the intake Lambda"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "Allow all outbound (to VPC endpoints and AWS services)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project   = "acme-health-intake"
    Workload  = "patient-intake-api"
    DataClass = "phi"
    ManagedBy = "terraform"
  }
}

# Gateway VPC endpoint for S3 — private route so the in-VPC Lambda reaches S3.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_vpc.main.main_route_table_id]

  tags = {
    Project   = "acme-health-intake"
    Workload  = "patient-intake-api"
    DataClass = "phi"
    ManagedBy = "terraform"
  }
}

# Gateway VPC endpoint for DynamoDB — private route so the in-VPC Lambda reaches DynamoDB.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_vpc.main.main_route_table_id]

  tags = {
    Project   = "acme-health-intake"
    Workload  = "patient-intake-api"
    DataClass = "phi"
    ManagedBy = "terraform"
  }
}

# GAP-07 support: the ENI permissions a VPC Lambda needs (create/delete/describe
# network interfaces). AWS packages these in this managed policy.
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}