package example_158

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    SlbType == "public"
    count(PublicIp) > 0
    count(MisConfigAcls) > 0
}

SlbType := input.SLB.Type
PublicIp := input.SLB.PublicIp


MisConfigAcls contains misconfigration if {
    some l in input.Listeners
    some acl in l.Acls[_].LoadBalancerAclEntrySet[_]
	acl.RuleAction == "allow"
    parts := split(acl.CidrBlock , "/")
	to_number(parts[1]) <= 8
    
    misconfigration := {
        "ListenerPort": l.Listener.ListenerPort,
        "ListenerProtocol": l.Listener.ListenerProtocol,
        "MisconfigrationACL" : acl
    }
}
