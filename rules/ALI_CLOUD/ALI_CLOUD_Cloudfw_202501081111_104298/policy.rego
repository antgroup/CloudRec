package cloudfw_forbidden_net_out_by_default_2400001
import rego.v1

default risk := false
risk if {
	unsafe_rule
    not forbidden_net_out_by_default
}

white_list := data.corpIpList_egress.corpIpList

policys contains p if  {
    some policy in input.Policys
    p := policy.Policy
    p.Direction == "out"
    p.Proto != "ICMP"
    not p.DestPort in ["53/53","123/123"]
}

default forbidden_net_out_by_default := false
forbidden_net_out_by_default if {
    some p in policys
    p.AclAction == "drop"
    p.Proto == "Any"
    p.Destination in ["0.0.0.0/0","Any"]
    p.Source in ["0.0.0.0/0", "Any"]
}

unsafe_rule if {
    some p in policys
    p.AclAction in ["log","accept"]
    p.Destination in ["0.0.0.0/0","Any"]
    not  p.Source in white_list
    some cidr in p.SourceGroupCidrs
    not cidr in white_list
}