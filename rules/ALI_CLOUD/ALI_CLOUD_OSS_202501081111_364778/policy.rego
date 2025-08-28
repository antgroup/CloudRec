package oss_bucket_policy_without_network_condition_2900001

import rego.v1

default risk := true

ip_conditions := {"IpAddress", "NotIpAddress"}

string_conditions := {"StringEquals", "StringNotEquals"}

risk = false if {
	policy := input.BucketPolicy.Statement[_]
	policy.Condition[ip_conditions[_]]
}

risk = false if {
	policy := input.BucketPolicy.Statement[_]
	policy.Condition[string_conditions[_]]["acs:SourceVpc"]
}

risk = false if {
	input.BucketInfo.ACL == "private"
}

risk = false if {
	input.BucketInfo.BlockPublicAccess == true
}

bucket_name := input.BucketInfo.Name