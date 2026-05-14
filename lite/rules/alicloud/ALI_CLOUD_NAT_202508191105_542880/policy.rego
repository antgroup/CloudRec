package cloudrec_12000001

import rego.v1

default risk := false

risk if {
	is_internet
	some entry in input.ForwardTableEntry
	entry_enabled(entry)
}

messages contains message if {
	is_internet
	some entry in input.ForwardTableEntry
	entry_enabled(entry)
	message := {
		"message": "公网 NAT Gateway 存在 DNAT 公网入口，应结合端口、目标资产和安全组/云防火墙确认是否符合预期。",
		"evidence": {
			"forward_entry_id": object.get(entry, "ForwardEntryId", ""),
			"external_ip": object.get(entry, "ExternalIp", ""),
			"external_port": object.get(entry, "ExternalPort", ""),
			"internal_ip": object.get(entry, "InternalIp", ""),
			"internal_port": object.get(entry, "InternalPort", ""),
			"ip_protocol": object.get(entry, "IpProtocol", ""),
		},
	}
}

is_internet if {
	lower(input.NatGateway.NetworkType) == "internet"
}

entry_enabled(entry) if {
	status := lower(object.get(entry, "Status", ""))
	status != "deleted"
}
