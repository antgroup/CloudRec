package ob_tx_cam_user_166

import rego.v1

default risk := false

risk if {
    count(root_ak) > 0
}
root_ak contains p if {
    input.AccessKeys != null
    some p in input.AccessKeys
    AccessKeyId :=p.AccessKeyId
    p.Status == "Active"
    input.AttachedUserPolicyDetail != null
    some p2 in input.AttachedUserPolicyDetail
    p2.AttachedUserPolicy.PolicyName == "AdministratorAccess"
    }
root_ak contains p if {
    input.AccessKeys != null
    some p in input.AccessKeys
    AccessKeyId :=p.AccessKeyId
    p.Status == "Active"
    input.AttachedUserPolicyDetail != null
    some p2 in input.AttachedUserPolicyDetail
    json.unmarshal(p2.PolicyDocument, parsed_policy)
    parsed_policy.statement != null
    some statement in parsed_policy.statement
    statement.action == "*"
    statement.effect == "allow"
    not statement.condition
    }
