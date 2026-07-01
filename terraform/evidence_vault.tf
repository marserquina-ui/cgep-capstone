# terraform/evidence_vault.tf
# Immutable evidence vault for signed compliance bundles from the pipeline.
# S3 Object Lock (COMPLIANCE mode) = write-once, delete-proof until retention expires.
# HIPAA 164.312(b) — Audit controls; chain-of-custody "preservation" leg.

resource "aws_s3_bucket" "evidence" {
  bucket = "${local.name_prefix}-evidence-vault-${local.suffix}"

  # Object Lock can ONLY be enabled at bucket creation — not added later.
  object_lock_enabled = true

  tags = {
    Project   = "acme-health-intake"
    Workload  = "patient-intake-api"
    DataClass = "phi"
    ManagedBy = "terraform"
  }
}

# Versioning is required for Object Lock to function.
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Default retention: every object locked for 1 year, COMPLIANCE mode.
# COMPLIANCE means not even the root account can delete before expiry.
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

# Encrypt evidence at rest with the same CMK as the rest of the workload.
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# Block all public access — evidence is never public.
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy      = true
  ignore_public_acls       = true
  restrict_public_buckets  = true
}

output "evidence_vault_bucket" {
  description = "S3 Object Lock vault holding signed evidence bundles from the pipeline"
  value       = aws_s3_bucket.evidence.id
}