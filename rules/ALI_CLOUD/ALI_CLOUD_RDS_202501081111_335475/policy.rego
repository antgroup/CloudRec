package rds_open_network_to_all_1700003

import rego.v1

default risk := false

risk if {
	count(security_ip_groups) > 0
	is_internet
}

## 一些基础信息，不一定是 InstanceId
## 实例网络信息，包含 ip 和 实例id
instance_info := input.DBInstance

## 定义检查规则

## 判断rds ip白名单是否包含 0.0.0.0/0
security_ip_groups contains groups if {
	some groups in input.DBInstanceIPArray
	contains(groups.SecurityIPList, "0.0.0.0/0")
}

## 判断nettype
is_internet if {
	input.DBInstanceAttribute.DBInstanceNetType == "Internet"
}
