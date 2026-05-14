package redis_open_network_to_all_1700002
import rego.v1

default risk := false
risk if {
	count(security_ip_groups) > 0
    is_public
}
messages contains message if {
    risk == true
    message := {
        "Description": "阿里云Redis实例开启了公网链接，且安全组配置了 0.0.0.0/0 允许全网访问",
        "NetInfo": is_public,
        "SecurityIpGroups": security_ip_groups,
    }
}


security_ip_groups contains groups if {
    some groups in input.SecurityIpGroups
    contains(groups.SecurityIpList, "0.0.0.0/0")
}

is_public := net if {
    some netInfo in input.InstanceNetInfo
    netInfo.IPType == "Public"
    net := {
        "ConnectionString": netInfo.ConnectionString,
        "IPAddress": netInfo.IPAddress,
        "Port": netInfo.Port,
        "IPType": netInfo.IPType,
    }
}