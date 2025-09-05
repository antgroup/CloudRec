package cloudrec_7900002
import rego.v1

default risk := false
risk if {
	count(opened_ports) > 0
	address_type == "internet"
}

# basic info
lb_id := input.LoadBalancerAttribute.LoadBalancerId

lb_name := input.LoadBalancerAttribute.LoadBalancerName

address := input.LoadBalancerAttribute.Address

standard_ports := {80, 443}

address_type := input.LoadBalancer.AddressType

# AclStatus set to 'off'
opened_ports contains {port: reason} if {
	some listener in input.Listeners
	not listener.Listener.ListenerPort in standard_ports
	listener.Listener.AclStatus == "off"

	port := listener.Listener.ListenerPort
	reason := "AclStatus set to 'off'"
}

# AclList config contains '0.0.0.0/0'
opened_ports contains {port: reason} if {
	some listener in input.Listeners
	listener.Listener.ListenerPort in standard_ports
	listener.Listener.AclType == "white"
	some acl in listener.AclList[_].AclEntrys[_]
	acl.AclEntryIP == "0.0.0.0/0"

	port := listener.Listener.ListenerPort
	reason := "AclList config contains '0.0.0.0/0'"
}

test contains acl if {
	some listener in input.Listeners

	some acl in listener.AclList[_].AclEntrys[_]
	acl.AclEntryIP == "0.0.0.0/0"
}