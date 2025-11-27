package tencent_iam_root_ak_121

import rego.v1

default risk := false

risk if {
    count(root_ak) != 0
}

root_ak contains p if {
    input.AccessKeys != null
    some p in input.AccessKeys
    AccessKeyId :=p.AccessKeyId
    p.Status == "active"
    input.AttachedUserPolicyDetail != null
    some p2 in input.AttachedUserPolicyDetail
    p2.AttachedUserPolicy.PolicyName == "AdministratorAccess"
    }
