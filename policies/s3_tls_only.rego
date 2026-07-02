# METADATA
# title: S3 bucket policies must deny non-TLS (insecure transport) access
# description: >-
#   Every aws_s3_bucket_policy must contain a statement with Effect "Deny"
#   and a Bool condition aws:SecureTransport = "false", enforcing TLS-only
#   access. The policy document is an escaped JSON string, so it is parsed
#   with json.unmarshal before inspection. Matches on statement shape, not
#   Sid, so it holds regardless of how the statement is named.
# custom:
#   framework: HIPAA Security Rule
#   controls: ["164.312(e)(1)"]
#   severity: high
package compliance.s3_tls_only

import rego.v1

bucket_policies contains resource if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_policy"
}

# A parsed statement enforces TLS if it Denies on aws:SecureTransport = false
enforces_tls(statement) if {
	statement.Effect == "Deny"
	statement.Condition.Bool["aws:SecureTransport"] == "false"
}

# Deny: a bucket policy with no TLS-enforcing statement
deny contains msg if {
	some resource in bucket_policies
	doc := json.unmarshal(resource.change.after.policy)
	not any_tls_statement(doc)
	msg := sprintf(
		"[HIPAA 164.312(e)(1)] S3 bucket policy on '%s' does not deny non-TLS access (missing aws:SecureTransport deny)",
		[object.get(resource.change.after, "bucket", "<computed>")],
	)
}

any_tls_statement(doc) if {
	some statement in doc.Statement
	enforces_tls(statement)
}
