package ecs_sg_public_open_1100001
import rego.v1

default risk := false
default min_priority_with_drop := false

risk if {
    has_public_address
    count(security_groups_to_all)>0
    min_priority_with_drop != true
}

## ecs 基础信息
instance_id := input.InstanceId
instance_name := input.InstanceName
public_ip_address := input.Instance.PublicIpAddress.IpAddress

has_public_address if {
    count(public_ip_address) > 0
}

security_groups_to_all contains p if {
    some p in input.SecurityGroups[_].Permissions
    p.SourceCidrIp == "0.0.0.0/0"
    p.PortRange in ["1/65535","-1/-1"]
    p.Direction == "ingress"
    p.IpProtocol in ["TCP","ALL"]
}
extract_key_values(input_array, key) = values if {
    values := [v | i := input_array[_]; v := to_number(i[key])]
}

min_priority_with_drop if {
    some p in security_groups_to_all
    to_number(p.Priority) == min(extract_key_values(security_groups_to_all,"Priority"))
    p.Policy == "Drop"
}
