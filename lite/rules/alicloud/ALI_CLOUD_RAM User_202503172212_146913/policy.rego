package ram_user_with_high_risk_access_has_no_acl_7200004
import rego.v1

default risk := false
risk if {
    input.ExistActiveAccessKey
    exist_Policies != null
    without_network_acl
    not covered_by_ip_address_control
    not covered_by_vpc_control
}
messages contains message if {
    risk == true
    message := {
        "Description": "账号拥有敏感权限，但部分权限未设置网络ACL",
        "RiskStatment": allow_sts_without_network_acl,
        "AKList": AccessKeys,
        "Policies": exist_Policies,
    }
}


exist_Policies := input.Policies
AccessKeys contains ak if {
    some AccessKey in input.AccessKeys[_]
    ak := AccessKey.AccessKeyId
}

without_network_acl if {
    count(allow_sts_without_network_acl) > 0
}

sensitive_actions := ["*", "*:*", "ecs:*", "rds:*", "oss:*", "ram:*", "*:List*","*:Put*","ram:Create*","ram:Attach*"]
read_only_actions := []
# full_access_actions := ["*", "*:*", "ecs:*", "rds:*", "oss:*", "ram:*"]
full_access_resource := "*"

allow_sts_without_network_acl contains {"Action":action,"Resource":resource} if {
    some policy in input.Policies
    policy_doc := json.unmarshal(policy.DefaultPolicyVersion.PolicyDocument)
    some sts in policy_doc.Statement
    sts.Effect == "Allow"
    not sts.Condition.IpAddress["acs:SourceIp"]
    not sts.Condition.StringLike["acs:SourceVpc"]
    action_str := get_str_to_array(sts.Action)
    action_arr := get_str_to_array(sts.Action)
    resource_str := get_str_to_array(sts.Resource)
    resource_arr := get_str_to_array(sts.Resource)
    action_all := array.concat(action_str, action_arr)
    resource_all := array.concat(resource_str, resource_arr)
    actions := get_full_access_actions(action_all)
    resource := get_full_access_resource(resource_all)
    action := actions[_]
}

get_str_to_array(ActionResource) := result if {
	type_name(ActionResource) == "string"
	result = [ActionResource]
} else := result if {
	type_name(ActionResource) == "array"
	result = ActionResource
}

get_full_access_actions(action_all) := actions if {
    actions := [action | action := action_all[_]; action in sensitive_actions]
}
#else if {
#    actions := [action | action := action_all[_]; action in sensitive_actions]
#}

get_full_access_resource(resource_all) := resource if {
    full_access_resource in resource_all
    resource := full_access_resource
}

deny_sts_with_ip_address_control contains {"Action":action, "Resource":resource} if {
    some policy in input.Policies
    policy_doc := json.unmarshal(policy.DefaultPolicyVersion.PolicyDocument)
    some sts in policy_doc.Statement
    sts.Effect == "Deny"
    sts.Condition.NotIpAddress["acs:SourceIp"]
    action_str := get_str_to_array(sts.Action)
    action_arr := get_str_to_array(sts.Action)
    resource_str := get_str_to_array(sts.Resource)
    resource_arr := get_str_to_array(sts.Resource)
    action_all := array.concat(action_str, action_arr)
    resource_all := array.concat(resource_str, resource_arr)
    action := action_all[_]
    resource := resource_all[_]
}
deny_sts_with_vpc_control contains {"Action":action, "Resource":resource} if {
    some policy in input.Policies
    policy_doc := json.unmarshal(policy.DefaultPolicyVersion.PolicyDocument)
    some sts in policy_doc.Statement
    sts.Effect == "Deny"
    sts.Condition.NotStringLike["acs:SourceVpc"]
    action_str := get_str_to_array(sts.Action)
    action_arr := get_str_to_array(sts.Action)
    resource_str := get_str_to_array(sts.Resource)
    resource_arr := get_str_to_array(sts.Resource)
    action_all := array.concat(action_str, action_arr)
    resource_all := array.concat(resource_str, resource_arr)
    action := action_all[_]
    resource := resource_all[_]
}

covered_by_ip_address_control if {
    every action_resource in allow_sts_without_network_acl {
        some acl in deny_sts_with_ip_address_control
        pattern_resource := replace(acl.Resource,"*",".*")
        pattern_action := replace(acl.Action,"*",".*")
        regex.match(pattern_resource,action_resource.Resource)
        regex.match(pattern_action,action_resource.Action)
    }
}

covered_by_vpc_control if {
    every action_resource in allow_sts_without_network_acl {
        some acl in deny_sts_with_vpc_control
        pattern_resource := replace(acl.Resource,"*",".*")
        pattern_action := replace(acl.Action,"*",".*")
        regex.match(pattern_resource,action_resource.Resource)
        regex.match(pattern_action,action_resource.Action)
    }
}