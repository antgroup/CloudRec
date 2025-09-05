package ecs_open_risk_port_to_pub_2200007

import rego.v1

default risk := false

risk if {
	count(sg_with_risk_ports) > count(min_priority_with_drop)
	has_public_address
}
messages contains message if {
	risk == true
	message := {
		"Description": "下列安全组将高危服务端口开放至互联网",
		"SecurityGroups": sg_with_risk_ports,
	}
}

public_ip_address := input.PublicAddress
has_public_address if {
	count(public_ip_address) > 0
}

## 定义高危端口
servicePorts := data.risk_default_ports.servicePorts

sg_with_risk_ports contains {servicePort: p} if {
	some p in input.SecurityGroups[_].Permissions
	parts := split(p.PortRange, "/")

	some servicePort in servicePorts

	## 这里 -1/-1 不参与。有规则重复的嫌疑
	servicePort.port <= to_number(parts[1]) # numbers.range(to_number(parts[0]), to_number(parts[1]))
    servicePort.port >= to_number(parts[0])
	p.SourceCidrIp == "0.0.0.0/0"
	p.Direction == "ingress"
}

# 提取指定键的值
extract_key_values(input_array, key) := values if {
	values := [v | i := input_array[_]; v := i[key]]
}

# 提取指定键的值，并将 values 从 str 转 int
extract_key_values_to_number(input_array, key) := values if {
	values := [v | i := input_array[_]; v := to_number(i[key])]
}

min_priority_with_drop contains p if {
	some servicePort in object.keys(sg_with_risk_ports[_])
	sg_with_risk_port := extract_key_values(sg_with_risk_ports, servicePort)
	some p in sg_with_risk_port
	to_number(p.Priority) == min(extract_key_values_to_number(sg_with_risk_port, "Priority"))
	p.Policy == "Drop"
}
