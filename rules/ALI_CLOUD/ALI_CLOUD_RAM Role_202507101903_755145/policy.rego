package ram_role_with_high_risk_access_10700002
import rego.v1

default risk := false
risk if {
    exist_Policies != null
    count(allow_sts) > 0
    uncovered_by_deny == true
}
messages contains message if {
    risk == true
    message := {
        "Description": "角色拥有敏感权限",
        "RiskStatment": allow_sts,
        "Policies": exist_Policies,
    }
}

exist_Policies := input.Policies

sensitive_actions := ["*", "*:*", "ecs:*", "rds:*", "oss:*", "ram:*", "*:List*","*:Put*","ram:Create*","ram:Attach*"]
read_only_actions := []
# full_access_actions := ["*", "*:*", "ecs:*", "rds:*", "oss:*", "ram:*"]
full_access_resource := "*"

allow_sts contains {"Action":action,"Resource":resource} if {
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

## Deny Statement with Condition
deny_sts contains {"Action":action, "Resource":resource} if {
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
    action := action_all[_]
    resource := resource_all[_]
}

uncovered_by_deny if {
    every action_resource in allow_sts {
        some sts in deny_sts
        pattern_resource := replace(sts.Resource,"*",".*")
        pattern_action := replace(sts.Action,"*",".*")
        regex.match(pattern_resource,action_resource.Resource)
        regex.match(pattern_action,action_resource.Action)
    }
}