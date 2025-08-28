package cloudrec_2300005

import rego.v1

default risk := false

## 根据下文的检查规则判断是否存在风险
risk if {
	acl_misconfiguration
}
risk if {
    acl_disabled
}

## 定义检查规则
acl_misconfiguration if {
    ip_list := input.GetProjectResponseBodyData.ipWhiteList.ipList
    "0.0.0.0/0" in split(ip_list, ",")
}

acl_misconfiguration if {
    ip_list := input.Project.ipWhiteList.ipList
    "0.0.0.0/0" in split(ip_list, ",")
}

acl_disabled if {
    not input.GetProjectResponseBodyData.ipWhiteList
}

project_name := input.Project.name