package kvstore_network_pub_proxy_2300004

import rego.v1

default risk := false

## 根据下文的检查规则判断是否存在风险
risk if {
	kvstore_network_pub_proxy
}

## 一些基础信息，不一定是 InstanceId
instance_id := input.KVStoreInstance.InstanceId
instance_name := input.KVStoreInstance.InstanceName



## 定义检查规则
kvstore_network_pub_proxy if {
    input.DBInstanceAttribute.NetworkType != "VPC"
    input.DBInstanceAttribute.ReplicationMode == "cluster"
}