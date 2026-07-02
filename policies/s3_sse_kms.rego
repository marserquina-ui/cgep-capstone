# METADATA
# title: S3 buckets must use CMK-based SSE-KMS encryption at rest
# description: >-
#   Every aws_s3_bucket_server_side_encryption_configuration must specify
#   sse_algorithm "aws:kms" (customer-managed KMS), not "AES256" (SSE-S3).
#   Checks the algorithm, not the key ARN, because the ARN may be a
#   computed value (null in plan) even when the config is compliant.
# custom:
#   framework: HIPAA Security Rule
#   controls: ["164.312(a)(2)(iv)"]
#   severity: high
package compliance.s3_sse_kms

import rego.v1

sse_configs contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
}

deny contains msg if {
	some resource in sse_configs
	some rule in resource.change.after.rule
	some enc_default in rule.apply_server_side_encryption_by_default
	enc_default.sse_algorithm != "aws:kms"
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] S3 bucket '%s' uses '%s' instead of CMK-based aws:kms encryption",
		[resource.change.after.bucket, enc_default.sse_algorithm],
	)
}
