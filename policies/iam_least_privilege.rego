# METADATA
# title: IAM inline policies must not grant Action:* on Resource:*
# description: >-
#   Customer-authored aws_iam_role_policy / aws_iam_policy documents must not
#   contain an Allow statement granting Action "*" on Resource "*" (full
#   admin). Action and Resource may each be a string or an array, so both are
#   normalized to sets before checking for the "*" wildcard. Scope note: only
#   inline/customer-managed policy documents are visible in the plan; attached
#   AWS-managed policies are not inspected.
# custom:
#   framework: HIPAA Security Rule
#   controls: ["164.312(a)(1)"]
#   severity: high
package compliance.iam_least_privilege

import rego.v1

iam_policies contains resource if {
	some resource in input.resource_changes
	resource.type in {"aws_iam_role_policy", "aws_iam_policy"}
}

# Normalize a string-or-array field into a set of values
to_set(v) := {v} if is_string(v)
to_set(v) := {x | some x in v} if is_array(v)

# A statement is over-privileged: Allow with Action:* AND Resource:*
overprivileged(statement) if {
	statement.Effect == "Allow"
	"*" in to_set(statement.Action)
	"*" in to_set(statement.Resource)
}

deny contains msg if {
	some resource in iam_policies
	doc := json.unmarshal(resource.change.after.policy)
	some statement in doc.Statement
	overprivileged(statement)
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] IAM policy '%s' grants Action:* on Resource:* (full admin, violates least privilege)",
		[object.get(resource.change.after, "name", "<computed>")],
	)
}
