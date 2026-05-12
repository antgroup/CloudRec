package nlb_exposed_high_risk_port_to_pub_3800004

import rego.v1

default risk := false

risk if {
	is_internet_network
	some listener in input.Listeners
	high_risk_listener(listener)
	not listener_blocked_by_security_group(listener)
}

is_internet_network if {
	lower(input.LoadBalancer.AddressType) == "internet"
}

servicePorts := data.risk_default_ports.servicePorts

high_risk_listener(listener) if {
	port := listener_port(listener)
	some servicePort in servicePorts
	port == servicePort.port
}

listener_port(listener) := port if {
	port := to_number(listener.Listener.ListenerPort)
}

listener_port(listener) := port if {
	port := to_number(listener.ListenerAttribute.ListenerPort)
}

listener_blocked_by_security_group(listener) if {
	port := listener_port(listener)
	some group in input.SecurityGroups
	some permission in group.Permissions
	blocks_public_listener(permission, port)
}

blocks_public_listener(permission, port) if {
	lower(permission.Direction) == "ingress"
	lower(permission.Policy) in {"drop", "deny"}
	public_source(permission.SourceCidrIp)
	port_range_covers(permission.PortRange, port)
}

public_source(source) if {
	source in {"0.0.0.0/0", "::/0"}
}

port_range_covers(port_range, port) if {
	parts := split(port_range, "/")
	start := to_number(parts[0])
	end := to_number(parts[1])
	port in numbers.range(start, end)
}

port_range_covers(port_range, port) if {
	port_range == "Any"
	port >= 1
}
