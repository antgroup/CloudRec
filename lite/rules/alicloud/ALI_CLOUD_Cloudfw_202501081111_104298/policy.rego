package cloudfw_forbidden_net_out_by_default_2400001
import rego.v1

default risk := false

risk if {
    p := input.Policy
    is_outbound(p)
    action_allows_traffic(p)
    not icmp_policy(p)
    not dns_or_ntp_exception(p)
    public_destination(p)
}

is_outbound(p) if {
    lower(p.Direction) == "out"
}

action_allows_traffic(p) if {
    lower(p.AclAction) in ["accept", "log"]
}

icmp_policy(p) if {
    lower(p.Proto) == "icmp"
}

dns_or_ntp_exception(p) if {
    p.DestPort in ["53", "53/53", "123", "123/123"]
}

public_destination(p) if {
    lower(p.Destination) in ["any", "0.0.0.0/0", "::/0"]
}

public_destination(p) if {
    some cidr in p.DestinationGroupCidrs
    lower(cidr) in ["0.0.0.0/0", "::/0"]
}
