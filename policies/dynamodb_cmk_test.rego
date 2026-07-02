package compliance.dynamodb_cmk

import rego.v1

# PASS: table with a customer-managed CMK ARN -> no denials
test_compliant_cmk_table if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_dynamodb_table",
		"change": {"after": {
			"name": "compliant-table",
			"server_side_encryption": [{
				"enabled": true,
				"kms_key_arn": "arn:aws:kms:us-east-1:560599485314:key/abc",
			}],
		}},
	}]}
}

# FAIL: encryption enabled but no customer CMK (AWS-managed key) -> one denial
test_aws_managed_key_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_dynamodb_table",
		"change": {"after": {
			"name": "aws-managed-table",
			"server_side_encryption": [{"enabled": true, "kms_key_arn": ""}],
		}},
	}]}
}

# FAIL: no encryption block at all (AWS-owned default key) -> one denial
test_no_encryption_block_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_dynamodb_table",
		"change": {"after": {"name": "unencrypted-table"}},
	}]}
}
