package polardb_open_to_pub_2200004
import rego.v1

default risk := false
risk if {
	count(acl_misconfiguraion) > 0
}
messages contains message if {
    risk == true
    message := {
        "Description": "阿里云PolarDB因为IP白名单设置不当导致对互联网开放",
        "ACL": acl_misconfiguraion
    }
}

## 定义检查规则
## 白名单设置 0.0.0.0/0
acl_misconfiguraion contains acl if {
    some acl in input.DBClusterAccessWhitelist.Items.DBClusterIPArray
    "0.0.0.0/0" in split(acl.SecurityIps, ",")
}

