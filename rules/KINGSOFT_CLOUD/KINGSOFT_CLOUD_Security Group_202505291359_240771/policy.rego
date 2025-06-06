package ksyun_sg_allin_150

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    count(SecurityGroupWithAll) != 0
}

SecurityGroupWithAll contains p if {
    some p in input.SecurityGroup.SecurityGroupEntrySet
    p.CidrBlock == "0.0.0.0/0"
    p.Direction == "in"
    p.PortRangeTo == null
    p.PortRangeFrom == null
    p.Protocol != "icmp"
}
