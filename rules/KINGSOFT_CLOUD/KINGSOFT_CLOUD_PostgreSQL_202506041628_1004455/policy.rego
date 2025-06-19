package example_163

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    count(misconfigrations) > 0
}

misconfigrations contains Info if {
    some sg in input.SecurityGroup
    some rule in sg.SecurityGroupRules
    isIpRangesAllowAll(rule.SecurityGroupRuleProtocol)

    Info := {
        "SecurityGroupId": sg.SecurityGroupId,
        "SecurityGroupName": sg.SecurityGroupName,
        "Rule": rule
    }
}

isIpRangesAllowAll(range) if {
    range in ["0.0.0.0/0", "::/0"]
}
