package cloudrec_6900003_160
import rego.v1

default risk := false
risk if {
	count(exist_port_exposed) > 0
    has_public_address
}
messages contains message if {
	risk == true
	message := {
		"Description": "There exists port(s) exposed",
		"UnrestrictedPermission": exist_port_exposed,
	}
}

public_ip_address := input.Instance.PublicIpAddress.IpAddress
has_public_address if {
    count(public_ip_address) > 0
}

exist_port_exposed contains {"port":port, "priority":allow_priority} if {
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
}else := min_denied_priority if {
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
unrestricted_allow_permission contains p if {
	some permission in input.SecurityGroups[_].Permissions
	permission.Policy = "Accept"
	permission.Direction == "ingress"
	permission.IpProtocol != "ICMP"
	permission.SourceCidrIp in unrestricted_cidr

	parts := split(permission.PortRange, "/")
	port_range := numbers.range(to_number(parts[0]),to_number(parts[1]))
	p := {
		"priority": to_number(permission.Priority),
		"port_range": port_range,
	}
}

restricted_deny_permission contains p if {
	some permission in input.SecurityGroups[_].Permissions
	permission.Policy = "Drop"
	permission.Direction == "ingress"
	permission.IpProtocol != "ICMP"
	permission.SourceCidrIp in unrestricted_cidr

	parts := split(permission.PortRange, "/")
	port_range := numbers.range(to_number(parts[0]),to_number(parts[1]))
	p := {
		"priority": to_number(permission.Priority),
		"port_range": port_range,
	}
}
