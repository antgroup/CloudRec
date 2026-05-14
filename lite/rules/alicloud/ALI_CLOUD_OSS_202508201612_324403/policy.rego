package oss_sse_algorithm_check_12100001
import rego.v1
default risk := false
risk if {
    not input.BucketInfo.SseRule.SSEAlgorithm
}
risk if {
    input.BucketInfo.SseRule.SSEAlgorithm == ""
}

bucket_name := input.BucketInfo.Name
sse_algorithm := input.BucketInfo.SseRule.SSEAlgorithm
acl := input.BucketInfo.ACL