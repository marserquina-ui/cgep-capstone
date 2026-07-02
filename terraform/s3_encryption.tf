# terraform/s3_encryption.tf
# GAP-01 — bring the uploads bucket under the customer CMK (SSE-KMS).
# HIPAA 164.312(a)(2)(iv) — Encryption and decryption.
# Replaces the starter's reliance on the AWS-owned SSE-S3 default key.

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
    bucket_key_enabled = true
  }
}