package cloudrec_10900001

import rego.v1

default risk := false

risk if {
	count(public_ip_addresses) > 0
	count(exist_port_exposed) > 0
}

risk if {
	count(public_ip_addresses) > 0
	input.SecurityGroups == null
}

messages contains message if {
	risk == true
	message := {
		"Description": "There exists port(s) exposed",
		"UnrestrictedPermission": exist_port_exposed,
		"Public IPs": public_ip_addresses,
		"Comment": "If UnrestrictedPermission is an empty list, it means that no security group is configured.",
	}
}

public_ip_addresses contains public_ip_address if {
	some i in input.Instance.PublicIpAddresses.PublicIpAddress
	public_ip_address := i.Ip
}

public_ip_addresses contains public_ip_address if {
	public_ip_address := input.EipAddress.EipAddress.IpAddress
}

exist_port_exposed contains {"port": port, "priority": allow_priority} if {
	some p in unrestricted_allow_permission
	allow_priority := p.priority
	some port in p.port_range
	denied_priority_list := get_denied_priority_list(port)
	min_denied_priority := get_min_denied_priority(denied_priority_list)
	min_denied_priority > allow_priority
}

get_min_denied_priority(denied_priority_list) := min_denied_priority if {
	count(denied_priority_list) > 0
	min_denied_priority = min(denied_priority_list)
} else := min_denied_priority if {
	count(denied_priority_list) = 0
	min_denied_priority := 101
}

get_denied_priority_list(port) := denied_priority_list if {
	denied_priority_list := [deny_priority |
		some p in restricted_deny_permission
		port in p.port_range
		deny_priority := p.priority
	]
}

unrestricted_cidr := {"0.0.0.0/0", "::/0"}

# https://help.aliyun.com/zh/ens/developer-reference/api-ens-2017-11-10-authorizesecuritygroup
risk_protocol := {"ALL", "TCP"}

unrestricted_allow_permission contains p if {
	some permission in input.SecurityGroups[_].Permissions.Permission
	permission.Policy == "Accept"
	permission.Direction == "ingress"
	permission.IpProtocol in risk_protocol
	permission.SourceCidrIp in unrestricted_cidr

	parts := split(permission.PortRange, "/")
	port_range := numbers.range(to_number(parts[0]), to_number(parts[1]))
	p := {
		"priority": to_number(permission.Priority),
		"port_range": port_range,
	}
}

restricted_deny_permission contains p if {
	some permission in input.SecurityGroups[_].Permissions.Permission
	permission.Policy == "Drop"
	permission.Direction == "ingress"
	permission.IpProtocol in risk_protocol
	permission.SourceCidrIp in unrestricted_cidr

	parts := split(permission.PortRange, "/")
	port_range := numbers.range(to_number(parts[0]), to_number(parts[1]))
	p := {
		"priority": to_number(permission.Priority),
		"port_range": port_range,
	}
}
