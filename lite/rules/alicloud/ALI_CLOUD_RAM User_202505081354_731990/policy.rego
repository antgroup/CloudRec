package ram_user_with_high_risk_access_has_no_acl_8900001
import rego.v1

default risk := false
risk if {
    exist_Policies != null
    count(account_assume_role) > 0
    count(security_group) <= 0
    count(ram_user) > 0
}

exist_Policies := input.Policies

# 判断是否可以被RAM来sts:AssumeRole
account_assume_role contains account if {
    assume_role_policies := json.unmarshal(input.Role.AssumeRolePolicyDocument)
    some statement in assume_role_policies.Statement
    statement.Action == "sts:AssumeRole"
    statement.Effect == "Allow"
    ram := object.get(statement.Principal, "RAM", [])
    count(ram) > 0
    account := ram
}

# 是否Security组
security_group contains sec if {
    desc := input.Role.Description
    regex.match(`(?i)security`, desc)
    sec := desc
}

ram_user contains {"Action":action, "Resource":resource} if {
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
    is_high_risk_condition(action_all, resource_all, policy)
    action := action_all[_]
    resource := resource_all[_]
}

is_high_risk_condition(action_all, resource_all, policy) if {
    policy.Policy.PolicyName == "AliyunRAMFullAccess"
} else := true if {
    some action in action_all
    action ==  "ram:*"
} else := true if {
    some action in action_all
    action ==  "ram:CreateUser"
} else := true if {
    some action in action_all
    action ==  "ram:UpdateUser"
} else := true if {
    some action in action_all
    action ==  "ram:CreatePolicy"
} else := true if {
    some action in action_all
    action ==  "ram:UpdatePolicy"
} else := true if {
    some action in action_all
    action ==  "ram:AttachPolicyToUser"
} else := true if {
    some action in action_all
    action ==  "ram:AttachPolicyToGroup"
} else := true if {
    some action in action_all
    action ==  "ram:AttachPolicyToRole"
} else := true if {
    some action in action_all
    action ==  "ram:CreateRole"
} else := true if {
    some action in action_all
    action ==  "ram:UpdateRole"
} else := true if {
    some action in action_all
    action ==  "ram:AssumeRole"
} else := true if {
    some action in action_all
    action ==  "ram:CreateAccessKey"
}

# 将字符串或数组转换为数组
get_str_to_array(ActionResource) := result if {
	type_name(ActionResource) == "string"
	result = [ActionResource]
} else := result if {
	type_name(ActionResource) == "array"
	result = ActionResource
}
