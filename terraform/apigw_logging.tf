# terraform/apigw_logging.tf
# GAP-08 (part 1) — CloudWatch log group for API Gateway access logs.
# HIPAA 164.312(b) — Audit controls.

resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigateway/${local.name_prefix}-intake-${local.suffix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.phi.arn

  tags = {
    Project   = "acme-health-intake"
    Workload  = "patient-intake-api"
    DataClass = "phi"
    ManagedBy = "terraform"
  }
}