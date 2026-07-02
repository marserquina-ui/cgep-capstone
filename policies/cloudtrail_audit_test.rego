package compliance.cloudtrail_audit

import rego.v1

# PASS: multi-region + validation + CMK -> no denials
test_compliant_trail if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_cloudtrail",
		"change": {"after": {
			"name": "good-trail",
			"is_multi_region_trail": true,
			"enable_log_file_validation": true,
			"kms_key_id": "arn:aws:kms:us-east-1:560599485314:key/abc",
		}},
	}]}
}

# FAIL: not multi-region -> one denial (core requirement unmet)
test_single_region_trail_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_cloudtrail",
		"change": {"after": {
			"name": "single-region-trail",
			"is_multi_region_trail": false,
			"enable_log_file_validation": true,
			"kms_key_id": "arn:aws:kms:us-east-1:560599485314:key/abc",
		}},
	}]}
}

# FAIL: compliant core but no CMK -> one denial (defense-in-depth)
test_trail_without_cmk_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_cloudtrail",
		"change": {"after": {
			"name": "no-cmk-trail",
			"is_multi_region_trail": true,
			"enable_log_file_validation": true,
		}},
	}]}
}

# FAIL: no trail at all -> one denial (vacuous-pass guard)
test_no_trail_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_s3_bucket",
		"change": {"after": {"bucket": "unrelated"}},
	}]}
}
