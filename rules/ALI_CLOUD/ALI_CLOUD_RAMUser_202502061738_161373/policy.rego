package cloudrec_5800001_162
import rego.v1

default risk := false
risk if {
    exist_AccessKey
    exist_Policies != null
    without_network_acl
    not covered_by_ip_address_control
    not covered_by_vpc_control
    count(ak_not_using_for_365_days) > 0
}

exist_AccessKey := input.ExistActiveAccessKey
exist_Policies := input.Policies
ActiveAccessKeys contains ak if {
    some AccessKey in input.AccessKeys[_]
    AccessKey.Status == "Active"
    ak := AccessKey.AccessKeyId
}

ram_aks := ActiveAccessKeys
now_ns := time.now_ns()
ak_not_using_for_365_days contains ak_id if {
   some ak_info in input.AccessKeys
   ak_info.AccessKey.Status == "Active"
   last_used_date_ns := time.parse_rfc3339_ns(ak_info.LastUsedDate)
   tmp := time.add_date(last_used_date_ns, 0, 0, 365)
   tmp < now_ns
   ak_id := ak_info.AccessKey.AccessKeyId
}


without_network_acl if {
    count(allow_sts_without_network_acl) > 0
}
without_network_acl if {
    count(deny_sts_without_network_acl) > 0
}

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
    action := action_all[_]
    resource := resource_all[_]
}

get_str_to_array(ActionResource) := result if {
	type_name(ActionResource) == "string"
	result = [ActionResource]
} else := result if {
	type_name(ActionResource) == "array"
	result = ActionResource
}

deny_sts_without_network_acl contains sts if {
    some policy in input.Policies
    policy_doc := json.unmarshal(policy.DefaultPolicyVersion.PolicyDocument)
    some sts in policy_doc.Statement
    sts.Effect == "Deny"
    not sts.Condition.NotIpAddress["acs:SourceIp"]
    not sts.Condition.NotStringLike["acs:SourceVpc"]
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