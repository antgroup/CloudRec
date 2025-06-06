package example_152

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    count(PublicIp) > 0
    count(SecurityGroupsToAll) > 0
    not min_priority_is_drop
}

InstanceId := input.Instance.InstanceId
InstanceName := input.Instance.InstanceName
PublicIp := input.Instance.NetworkInterfaceSet[_].PublicIp

SecurityGroupsToAll contains sge if {
    some sge in input.SecurityGroups[_].SecurityGroup.SecurityGroupEntrySet
    sge.Direction == "in"
    cidr_allowed(sge.CidrBlock)
    protocol_allowed(sge.Protocol)
    port_allowed(sge.PortRangeFrom, sge.PortRangeTo)
}

protocol_allowed(protocol) if {
    protocol in ["tcp", "ip"]
}

cidr_allowed(cidr) if {
    "0.0.0.0/0" == cidr
}else if {
    "::/0" == cidr
}

port_allowed(PortRangeFrom, PortRangeTo) if {
    PortRangeFrom == null
    PortRangeTo == null
}


extract_key_values(input_array, key) = values if {
    values := [v | i := input_array[_]; v := i[key]]
}

min_priority_is_drop if {
    some p in SecurityGroupsToAll
    p.Priority == min(extract_key_values(SecurityGroupsToAll,"Priority"))
    p.Policy == "Drop"
}