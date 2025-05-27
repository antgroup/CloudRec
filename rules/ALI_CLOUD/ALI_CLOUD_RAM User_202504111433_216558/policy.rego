package cloudrec_8200001_153
import rego.v1

default risk := false
risk if {
    input.ExistActiveAccessKey == true
    not allow_covered_by_deny
    count(allow_sts_with_oss) > 0
}
messages contains message if {
    risk == true
    message := {
        "Description": "原始Policy",
        "result": input.Policies
    }
}
messages contains message if {
    risk == true
    message := {
        "Description": "账号下AK列表",
        "AKs": ActiveAccessKeys
    }
}

ActiveAccessKeys contains ak if {
    some AccessKey in input.AccessKeys[_]
    AccessKey.Status == "Active"
    ak := AccessKey.AccessKeyId
}

## 综合 allow策略、无条件deny策略，来综合判断一个账号是否可访问OSS
allow_sts_with_oss contains  {"Action":action, "Resource":resource} if {
    some policy in input.Policies
    policy_doc := json.unmarshal(policy.DefaultPolicyVersion.PolicyDocument)
    some sts in policy_doc.Statement
    sts.Effect == "Allow"
    action_str := get_str_to_array(sts.Action)
    action_arr := get_str_to_array(sts.Action)
    resource_str := get_str_to_array(sts.Resource)
    resource_arr := get_str_to_array(sts.Resource)
    action_all := array.concat(action_str, action_arr)
    resource_all := array.concat(resource_str, resource_arr)
    some action in action_all
    action_has_oss(action)
    some resource in resource_all
    resource_has_oss(resource)
}

get_str_to_array(ActionResource) := result if {
	type_name(ActionResource) == "string"
	result = [ActionResource]
} else := result if {
	type_name(ActionResource) == "array"
	result = ActionResource
}

deny_sts_without_condition contains  {"Action":action, "Resource":resource} if {
    some policy in input.Policies
    policy_doc := json.unmarshal(policy.DefaultPolicyVersion.PolicyDocument)
    some sts in policy_doc.Statement
    sts.Effect == "Deny"
    not sts.Condition
    action_str := get_str_to_array(sts.Action)
    action_arr := get_str_to_array(sts.Action)
    resource_str := get_str_to_array(sts.Resource)
    resource_arr := get_str_to_array(sts.Resource)
    action_all := array.concat(action_str, action_arr)
    resource_all := array.concat(resource_str, resource_arr)
    some action in action_all
    action_has_oss(action)
    some resource in resource_all
    resource_has_oss(resource)
}

action_has_oss(action) if {
    pattern := replace(split(action,":")[0],"*",".*")
    regex.match(pattern,"oss")
}
resource_has_oss(resource) if {
    startswith(resource, "acs:oss")
}else if {
    resource == "*"
}

allow_covered_by_deny if {
    every allow in allow_sts_with_oss {
        some deny in deny_sts_without_condition
        pattern_resource := replace(deny.Resource,"*",".*")
        pattern_action := replace(deny.Action,"*",".*")
        regex.match(pattern_resource,allow.Resource)
        regex.match(pattern_action,allow.Action)
    }
}