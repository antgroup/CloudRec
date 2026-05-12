package cloudrec_3600010
import rego.v1

default risk := false
risk if {
	has_internet_endpoint
    count(misconfig) > 0
}
messages contains message if {
    risk == true
    message := {
        "Description": "阿里云容器镜像服务未配置公网访问控制",
        "ACL": misconfig
    }
}

has_internet_endpoint if {
    input.InstanceInternetEndpoint.Domains[_].Domain
    input.InstanceInternetEndpoint.Status == "RUNNING"
}

misconfig contains acl if {
    acl := input.InstanceInternetEndpoint.AclEntries[_]
    acl.Entry == "0.0.0.0/0"
}

# 删除所有白名单后，公网下机器均可通过凭证访问企业版实例
# https://help.aliyun.com/zh/acr/user-guide/configure-access-over-the-internet
misconfig contains acl if {
    not input.InstanceInternetEndpoint.AclEntries
    acl := null
}