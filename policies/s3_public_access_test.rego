package compliance.s3_public_access

import rego.v1

# PASS: all four flags true -> no denials
test_compliant_public_access_block if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_s3_bucket_public_access_block",
		"change": {"after": {
			"bucket": "locked-bucket",
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		}},
	}]}
}

# FAIL: one flag explicitly false -> one denial
test_flag_false_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_s3_bucket_public_access_block",
		"change": {"after": {
			"bucket": "leaky-bucket",
			"block_public_acls": true,
			"block_public_policy": false,
			"ignore_public_acls": true,
			"restrict_public_buckets": true,
		}},
	}]}
}

# FAIL: one flag missing (defaults false in AWS) -> one denial
test_flag_missing_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_s3_bucket_public_access_block",
		"change": {"after": {
			"bucket": "partial-bucket",
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
		}},
	}]}
}
