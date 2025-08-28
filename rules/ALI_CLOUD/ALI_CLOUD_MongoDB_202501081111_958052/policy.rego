package mongodb_open_network_to_all_1700001
import rego.v1

default risk := false
risk if {
	count(security_ip_groups) > 0
    network_type_is_not_vpc
}

## 一些基础信息，不一定是 InstanceId
instance_info:= input.DBInstance
## 专有网络免密访问
vpc_auth_mode := input.DBInstanceAttribute.VpcAuthMode

## 判断mongodb白名单是否包含 0.0.0.0/0
security_ip_groups contains groups if {
    some groups in input.SecurityIpGroups
    contains(groups.SecurityIpList, "0.0.0.0/0")
}

network_type_is_not_vpc if {
    input.DBInstanceAttribute.ReplicaSets.ReplicaSet[_].NetworkType != "VPC"
}

