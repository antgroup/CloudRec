package example_153

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    count(PublicIp) > 0
    count(SecurityGroupsWithRiskPorts) > count(SecurityGroupsOfDrop)
}

PublicIp := input.Instance.NetworkInterfaceSet[_].PublicIp

## 定义高危端口
servicePorts := data.risk_default_ports.servicePorts

SecurityGroupsWithRiskPorts contains {servicePort:sge} if {
    some sge in input.SecurityGroups[_].SecurityGroup.SecurityGroupEntrySet
    sge.Direction == "in"
    cidr_allowed(sge.CidrBlock)
    protocol_allowed(sge.Protocol)
    some servicePort in servicePorts
    port_allowed(servicePort.port, sge.PortRangeFrom, sge.PortRangeTo)
}

protocol_allowed(protocol) if {
    protocol in ["tcp", "ip"]
}

cidr_allowed(cidr) if {
    "0.0.0.0/0" == cidr
}else if {
    "::/0" == cidr
}

port_allowed(target, PortRangeFrom, PortRangeTo) if {
    PortRangeFrom == null
    PortRangeTo == null
}else if {
    target in numbers.range(to_number(PortRangeFrom),to_number(PortRangeTo))
}

# 提取指定键的值
extract_key_values(input_array, key) = values if {
    values := [v | i := input_array[_]; v := i[key]]
}

SecurityGroupsOfDrop contains p if {
    some servicePort in object.keys(servicePorts)
    sg_with_risk_port := extract_key_values(SecurityGroupsWithRiskPorts, servicePort)
    some p in sg_with_risk_port
    p.Priority == min(extract_key_values(SecurityGroupsWithRiskPorts,"Priority"))
    p.Policy == "Drop"
}