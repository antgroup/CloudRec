package example_174

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    count(input.AccessKeys) > 0
    count(allow_sts_with_oss) > 0
}

messages contains message if {
    risk == true
    message := {
        "Description": "账号下AK列表",
        "AKs": input.AccessKeys[_].AccessKeyId
    }
}

## 综合 allow策略、无条件deny策略，来综合判断一个账号是否可访问BUCKET
allow_sts_with_oss contains  {"PolicyName":policy.Policy.PolicyName, "Action":action, "Resource":resource} if {
    some policy in input.AttachedUserPolicies
    policy_doc := json.unmarshal(policy.Document)
    some sts in policy_doc.Statement
    sts.Effect == "Allow"
    action_arr := get_str_to_array(sts.Action)
    resource_arr := get_str_to_array(sts.Resource)
    some action in action_arr
    action_has_oss(action)
    some resource in resource_arr
    resource_has_oss(resource)
}

get_str_to_array(ActionResource) := result if {
	type_name(ActionResource) == "string"
	result = [ActionResource]
} else := result if {
	type_name(ActionResource) == "array"
	result = ActionResource
}

action_has_oss(action) if {
    pattern := replace(split(action,":")[0],"*",".*")
    regex.match(pattern,"ks3")
}
resource_has_oss(resource) if {
    contains(resource, "ks3")
}else if {
    resource == "*"
}

