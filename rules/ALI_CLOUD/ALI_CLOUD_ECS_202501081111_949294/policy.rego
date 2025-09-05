package ecs_public_open_rule_1200003
import rego.v1

default risk := false
risk if {
    count(sg_with_22) > 0
    count(min_priority_with_drop) = 0
    has_public_address
}

## ecs 基础信息
instance_id := input.InstanceId
instance_name := input.InstanceName
public_ip_address := input.Instance.PublicIpAddress.IpAddress

has_public_address if {
    count(public_ip_address) > 0
}

sg_with_22 contains p if {
    some p in input.SecurityGroups[_].Permissions
    parts := split(p.PortRange, "/")
    
    ## 这里 -1/-1 不参与。有规则重复的嫌疑
    22 in numbers.range(to_number(parts[0]),to_number(parts[1]))
    p.SourceCidrIp == "0.0.0.0/0"
    p.Direction == "ingress"
}

# 提取指定键的值
extract_key_values(input_array, key) = values if {
    values := [v | i := input_array[_]; v := to_number(i[key])]
}

min_priority_with_drop contains p if {
    some p in sg_with_22
    to_number(p.Priority) == min(extract_key_values(sg_with_22,"Priority"))
    p.Policy == "Drop" 
}
