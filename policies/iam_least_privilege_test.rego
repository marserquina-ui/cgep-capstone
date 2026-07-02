package compliance.iam_least_privilege

import rego.v1

# PASS: scoped policy (specific actions + specific ARN) -> no denials
test_compliant_scoped_policy if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_iam_role_policy",
		"change": {"after": {
			"name": "scoped-policy",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Scoped\",\"Effect\":\"Allow\",\"Action\":[\"dynamodb:GetItem\",\"dynamodb:PutItem\"],\"Resource\":\"arn:aws:dynamodb:us-east-1:560599485314:table/intake\"}]}",
		}},
	}]}
}

# FAIL (string shape): Action:"*" on Resource:"*" -> one denial
test_wildcard_admin_string_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_iam_role_policy",
		"change": {"after": {
			"name": "admin-string",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Admin\",\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
		}},
	}]}
}

# FAIL (array shape): Action:["*"] on Resource:["*"] -> one denial
test_wildcard_admin_array_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_iam_policy",
		"change": {"after": {
			"name": "admin-array",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Admin\",\"Effect\":\"Allow\",\"Action\":[\"*\"],\"Resource\":[\"*\"]}]}",
		}},
	}]}
}
