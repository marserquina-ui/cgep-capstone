# METADATA
# title: A multi-region CloudTrail with log-file validation must exist
# description: >-
#   HIPAA Audit Controls require a complete, tamper-evident audit trail.
#   At least one aws_cloudtrail must exist with is_multi_region_trail = true
#   (complete coverage, AU-2/AU-12) and enable_log_file_validation = true
#   (tamper-evidence, AU-10). CMK encryption of the trail is checked
#   separately as defense-in-depth, at lower severity. The absence of any
#   trail is itself a violation, guarded explicitly so it cannot vacuously pass.
# custom:
#   framework: HIPAA Security Rule
#   controls: ["164.312(b)"]
#   severity: high
package compliance.cloudtrail_audit

import rego.v1

trails contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
}

# A trail meets the core audit-control requirement
compliant_trail(trail) if {
	trail.change.after.is_multi_region_trail == true
	trail.change.after.enable_log_file_validation == true
}

# Deny: no CloudTrail resource exists at all
deny contains msg if {
	count(trails) == 0
	msg := "[HIPAA 164.312(b)] No CloudTrail trail found; audit logging is not configured"
}

# Deny: no trail meets the multi-region + log-file-validation requirement
deny contains msg if {
	count(trails) > 0
	not any_compliant_trail
	msg := "[HIPAA 164.312(b)] No CloudTrail trail is both multi-region and has log-file validation enabled"
}

any_compliant_trail if {
	some trail in trails
	compliant_trail(trail)
}

# Lower-severity: a trail exists but is not CMK-encrypted (defense-in-depth)
deny contains msg if {
	some trail in trails
	compliant_trail(trail)
	not trail.change.after.kms_key_id
	msg := sprintf(
		"[HIPAA 164.312(b)] CloudTrail '%s' is not encrypted with a customer-managed KMS key (defense-in-depth)",
		[trail.change.after.name],
	)
}
