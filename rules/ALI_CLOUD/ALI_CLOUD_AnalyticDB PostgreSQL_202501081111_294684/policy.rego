package adb_postgreSQL_open_to_pub_2200005

import rego.v1

default risk := false

## 根据下文的检查规则判断是否存在风险
risk if {
	acl_misconfiguraion
    has_public_address
}

## 一些基础信息，不一定是 InstanceId
instance_id := input.DBInstance.DBInstanceId
instance_description := input.DBInstance.DBInstanceDescription

## 定义检查规则
## 白名单设置 0.0.0.0/0
acl_misconfiguraion if {
    some acl in input.DBInstanceIPArray
    "0.0.0.0/0" in split(acl.SecurityIPList, ",")
}

has_public_address if {
    ip_type := input.DBInstanceNetInfos.DBInstanceNetInfo[_].IPType
    ip_type == "Public"
}

