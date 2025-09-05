package hbase_exposed_to_pub_3300001
import rego.v1

default risk := false
risk if {
    has_internet_connect_address
    is_network_acl_exposed_to_all
}

has_internet_connect_address if {
    input.ConnAddrInfo[_].NetType == "PUBLIC"
}

is_network_acl_exposed_to_all if {
    some group in input.Group
    ip_list := group.IpList.Ip
    "0.0.0.0/0" in ip_list
}