#############################################
# cloudtrail.tf
# Layer 1 — Multi-region CloudTrail (CMK-encrypted, validated)
# Controls: HIPAA 164.312(b) Audit Controls
#           NIST AU-2 / AU-12 (event capture), AU-10 (log-file validation)
#############################################

# ---- Dedicated log bucket (separate from the Object Lock evidence vault) ----
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "cgep-capstone-cloudtrail-560599485314"

  tags = {
    Name    = "cgep-capstone-cloudtrail-logs"
    Purpose = "cloudtrail-audit-logs"
    Control = "HIPAA-164.312-b"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---- Bucket policy: CloudTrail service write access + TLS-only ----
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:us-east-1:560599485314:trail/cgep-capstone-trail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/560599485314/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:us-east-1:560599485314:trail/cgep-capstone-trail"
          }
        }
      },
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

# ---- The trail ----
resource "aws_cloudtrail" "main" {
  name           = "cgep-capstone-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  kms_key_id = "arn:aws:kms:us-east-1:560599485314:key/928c98bc-199b-4294-97ba-5f600ec23691"

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = {
    Name    = "cgep-capstone-trail"
    Control = "HIPAA-164.312-b"
  }
}
