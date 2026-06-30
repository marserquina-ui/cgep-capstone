# terraform/s3_versioning.tf
# GAP-04 — enable versioning on the uploads bucket so PHI overwrites/deletes are recoverable.
# HIPAA 164.308(a)(7) — Contingency plan (data backup / recoverability).

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}