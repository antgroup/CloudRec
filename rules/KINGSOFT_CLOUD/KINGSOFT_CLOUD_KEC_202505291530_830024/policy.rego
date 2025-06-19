package example_151

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    count(PublicIP) > 0
    count(SecurityGroupsWith22) > 0
    count(min_priority_with_drop) == 0
}

InstanceId := input.Instance.InstanceId
InstanceName := input.Instance.InstanceName
PublicIP := input.Instance.NetworkInterfaceSet[_].PublicIp


SecurityGroupsWith22 contains sge if {
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
}else if {
    22 in numbers.range(to_number(PortRangeFrom),to_number(PortRangeTo))
}

# 提取指定键的值
extract_key_values(input_array, key) = values if {
    values := [v | i := input_array[_]; v := i[key]]
}

min_priority_with_drop contains p if {
    some p in SecurityGroupsWith22
    p.Priority == min(extract_key_values(SecurityGroupsWith22,"Priority"))
    p.Policy == "Drop" 
}
