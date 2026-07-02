# METADATA
# title: S3 public access block must have all four protections enabled
# description: >-
#   Every aws_s3_bucket_public_access_block must set all four flags to true:
#   block_public_acls, block_public_policy, ignore_public_acls,
#   restrict_public_buckets. Uses "not true" rather than "== false" because an
#   omitted flag defaults to false (insecure) in AWS, so absence must also fail.
#   Scope note: validates configuration of existing blocks; it does not enforce
#   that every bucket has a block (that requires cross-resource correlation).
# custom:
#   framework: HIPAA Security Rule
#   controls: ["164.312(a)(1)"]
#   severity: high
package compliance.s3_public_access

import rego.v1

pab_resources contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_public_access_block"
}

required_flags := [
	"block_public_acls",
	"block_public_policy",
	"ignore_public_acls",
	"restrict_public_buckets",
]

deny contains msg if {
	some resource in pab_resources
	some flag in required_flags
	not flag_enabled(resource, flag)
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] S3 public access block on '%s' does not enable '%s' (must be true)",
		[resource.change.after.bucket, flag],
	)
}

# A flag is "enabled" only if present and exactly true.
# not flag_enabled(...) is therefore true for both false AND missing flags.
flag_enabled(resource, flag) if {
	resource.change.after[flag] == true
}
