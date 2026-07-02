package compliance.s3_sse_kms

import rego.v1

# PASS: bucket encrypted with aws:kms (CMK) -> no denials
test_compliant_kms_bucket if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {"after": {
			"bucket": "compliant-bucket",
			"rule": [{"apply_server_side_encryption_by_default": [{
				"sse_algorithm": "aws:kms",
				"kms_master_key_id": "arn:aws:kms:us-east-1:560599485314:key/abc",
			}]}],
		}},
	}]}
}

# FAIL: bucket using AES256 (SSE-S3) -> exactly one denial
test_aes256_bucket_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_s3_bucket_server_side_encryption_configuration",
		"change": {"after": {
			"bucket": "weak-bucket",
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
		}},
	}]}
}
