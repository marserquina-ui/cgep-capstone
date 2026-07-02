# METADATA
# title: DynamoDB tables must use a customer-managed CMK for encryption at rest
# description: >-
#   Every aws_dynamodb_table must have a server_side_encryption block with a
#   kms_key_arn (customer-managed CMK). Denies the default AWS-owned key
#   (block absent) and the AWS-managed key (enabled but no kms_key_arn).
#   Checks for the presence of kms_key_arn, not its literal value, since the
#   ARN may be a computed value in a fresh plan.
# custom:
#   framework: HIPAA Security Rule
#   controls: ["164.312(a)(2)(iv)"]
#   severity: high
package compliance.dynamodb_cmk

import rego.v1

tables contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_dynamodb_table"
}

# Deny: no server_side_encryption block at all (AWS-owned key)
deny contains msg if {
	some resource in tables
	not resource.change.after.server_side_encryption
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] DynamoDB table '%s' has no customer-managed CMK (uses default AWS-owned key)",
		[object.get(resource.change.after, "name", "<computed>")],
	)
}

# Deny: encryption block present but no customer CMK ARN (AWS-managed key)
deny contains msg if {
	some resource in tables
	some sse in resource.change.after.server_side_encryption
	not sse.kms_key_arn
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] DynamoDB table '%s' uses an AWS-managed key, not a customer-managed CMK",
		[object.get(resource.change.after, "name", "<computed>")],
	)
}
