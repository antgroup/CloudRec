package example_173

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false

risk if {
	count(using_high_risk_access) > 0
}

user_name := input.User.UserName

using_high_risk_access contains {"PolicyName":p, "Description":policy.Policy.Description} if {
    some policy in input.AttachedUserPolicies
    p := policy.Policy.PolicyName
    some al in ["FullAccess","AdministratorAccess"]
    contains(p, al)
}

