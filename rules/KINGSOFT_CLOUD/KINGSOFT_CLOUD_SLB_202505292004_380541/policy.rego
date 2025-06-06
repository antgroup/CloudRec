package example_156

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    SlbType == "public"
    count(PublicIp) > 0
    count(opened_ports) > 0
}

SlbType := input.SLB.Type
PublicIp := input.SLB.PublicIp
LbId := input.SLB.LoadBalancerId
LbName := input.SLB.LoadBalancerName

standard_ports := {80, 443}

# AclStatus set to 'off'
opened_ports contains {port: reason} if {
	some listener in input.Listeners
	not listener.Listener.ListenerPort in standard_ports
	listener.Acls == null

	port := listener.Listener.ListenerPort
	reason := "AclStatus set to 'off'"
}

# AclList config contains '0.0.0.0/0'
opened_ports contains {port: reason} if {
	some listener in input.Listeners
	not listener.Listener.ListenerPort in standard_ports
	some acl in listener.Acls[_].LoadBalancerAclEntrySet[_]
	acl.CidrBlock == "0.0.0.0/0"
    acl.RuleAction == "allow"

	port := listener.Listener.ListenerPort
	reason := "AclList config contains '0.0.0.0/0'"
}
