package compliance.s3_tls_only

import rego.v1

# PASS: policy contains a Deny on aws:SecureTransport=false -> no denials
test_compliant_tls_policy if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_s3_bucket_policy",
		"change": {"after": {
			"bucket": "compliant-bucket",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyNonTLS\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::compliant-bucket/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}",
		}},
	}]}
}

# FAIL: policy with only an Allow, no TLS deny -> one denial
test_missing_tls_deny_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_s3_bucket_policy",
		"change": {"after": {
			"bucket": "weak-bucket",
			"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowRead\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::weak-bucket/*\"}]}",
		}},
	}]}
}
