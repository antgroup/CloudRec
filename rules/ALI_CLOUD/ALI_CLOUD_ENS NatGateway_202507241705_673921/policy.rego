package cloudrec_11000001

import rego.v1

default risk := false

# case 1: have open ports and acls
risk if {
	count(opened_ports) > 0
}

# case 2: have dnat rules and no acl rules
risk if {
	count(port_to_ips) > 0
	input.ENSNetwork == null
}

messages contains message if {
	risk == true
	message := {
		"Description": "There exists port(s) exposed",
		"Open ports": opened_ports,
	}
}

# 1. have accept no drop rule
opened_ports contains {port: ips} if {
	some port, ips in port_to_ips
	accept_port_to_priority[port]
	not drop_port_to_priority[port]
}

# 2. have accept and drop rule, but accept have higher priority
opened_ports contains {port: ips} if {
	some port, ips in port_to_ips
	accept_port_to_priority[port]
	drop_port_to_priority[port]
	accept_port_to_priority[port] < drop_port_to_priority[port]
}

# 3. open to all (have accept no drop rule)
opened_ports contains {port: ips} if {
	port := -1
	accept_port_to_priority[port]
	not drop_port_to_priority[port]
	ips := {ip |
		some port, ips in port_to_ips
		some ip in ips
	}
}

# 4. open to all (have accept and drop rule, but accept have higher priority)
opened_ports contains {port: ips} if {
	port := -1
	accept_port_to_priority[port]
	drop_port_to_priority[port]
	accept_port_to_priority[port] < drop_port_to_priority[port]
	ips := {ip |
		some port, ips in port_to_ips
		some ip in ips
	}
}

# dnat rule and their ips
port_to_ips := {port: ips |
	some entry in input.ForwardTableEntries
	ports := get_ports(entry.ExternalPort)
	some port in ports
	ips := [ip |
		some entry in input.ForwardTableEntries
		ports := get_ports(entry.ExternalPort)
		port in ports
		ip := entry.ExternalIp
	]
}

unrestricted_cidr := {"0.0.0.0/0", "::/0"}
risk_protocol := {"all", "tcp"}

# accept ports and their priority
accept_port_to_priority := {port: priority |
	some acl in input.ENSNetwork.NetworkAcl.IngressAclEntries
	acl.Policy == "accept"
	acl.CidrBlock in unrestricted_cidr
	acl.Protocol in risk_protocol
	ports := get_ports(acl.PortRange)

	some port in ports
	priorities := [p |
		some acl in input.ENSNetwork.NetworkAcl.IngressAclEntries
		acl.Policy == "accept"
		acl.CidrBlock in unrestricted_cidr
		acl.Protocol in risk_protocol
		ports := get_ports(acl.PortRange)
		port in ports
		p := acl.Priority
	]
	priority := min(priorities)
}

# drop ports and their priority
drop_port_to_priority := {port: priority |
	some acl in input.ENSNetwork.NetworkAcl.IngressAclEntries
	acl.Policy == "drop"
	acl.CidrBlock in unrestricted_cidr
	acl.Protocol in risk_protocol
	ports := get_ports(acl.PortRange)

	some port in ports
	priorities := [p |
		some acl in input.ENSNetwork.NetworkAcl.IngressAclEntries
		acl.Policy == "drop"
		acl.CidrBlock in unrestricted_cidr
		acl.Protocol in risk_protocol
		ports := get_ports(acl.PortRange)
		port in ports
		p := acl.Priority
	]
	priority := min(priorities)
}

# helper function
get_ports(entry) := ports if {
	ports := [port |
		port_ranges := split(entry, ",")
		some port_range in port_ranges
		parts := split(port_range, "/")
		ports := numbers.range(to_number(parts[0]), to_number(parts[0]))
		some port in ports
	]
}
