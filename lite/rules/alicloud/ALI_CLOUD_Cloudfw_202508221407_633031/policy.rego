package cloudfw_open_unstandard_port_12200004
import rego.v1
default risk := false

risk if {
    action_allows_traffic
    not icmp_policy
    non_standard_port
    public_scope_for_direction
}

standard_ports := {"80", "80/80", "443", "443/443"}
AclUuid := input.Policy.AclUuid

action_allows_traffic if {
    lower_string(input.Policy.AclAction) in {"accept", "log"}
}

icmp_policy if {
    lower_string(input.Policy.Proto) == "icmp"
}

non_standard_port if {
    port := lower_string(input.Policy.DestPort)
    port != ""
    not port in standard_ports
}

public_scope_for_direction if {
    lower_string(input.Policy.Direction) == "in"
    public_source
}

public_scope_for_direction if {
    lower_string(input.Policy.Direction) == "out"
    public_destination
}

public_source if {
    public_value(input.Policy.Source)
}

public_source if {
    some cidr in input.Policy.SourceGroupCidrs
    public_value(cidr)
}

public_destination if {
    public_value(input.Policy.Destination)
}

public_destination if {
    some cidr in input.Policy.DestinationGroupCidrs
    public_value(cidr)
}

public_value(value) if {
    lower_string(value) in {"any", "0.0.0.0/0", "::/0"}
}

lower_string(value) := lower(trim_space(sprintf("%v", [value])))
