package clickhouse_open_to_pub_3800007
import rego.v1

default risk := false
risk if {
	has_public_address
    acl_misconfig
}

has_public_address if {
    some net_info in input.NetInfoItem
    net_info.NetType == "Public"
}

acl_misconfig if {
    some ip_list in input.IPArray
    ip_array := split(ip_list.SecurityIPList, ",")
    some ip in ip_array
	size := to_number(split(ip,"/")[1])
    size <= 8
}