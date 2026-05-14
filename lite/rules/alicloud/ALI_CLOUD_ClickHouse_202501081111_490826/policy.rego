package clickhouse_open_to_pub_3800006
import rego.v1


default risk := false

risk if {
	has_public_address

}

has_public_address if {
    some net_info in input.NetInfoItem
    net_info.NetType == "Public"
}

DBClusterDescription:=input.DBCluster.DBClusterDescription
