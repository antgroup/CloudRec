package es_open_to_pub_2200001
import rego.v1

default risk := false
risk if {
    misconfiguration
}

instance_id := input.InstanceDetail.instanceId
instance_description := input.InstanceDetail.description

## ES 公网开放到 0.0.0.0/0
misconfiguration if {
    some white_ip_group in input.InstanceDetail.networkConfig.whiteIpGroupList
    white_ip_group.whiteIpType == "PUBLIC_ES"
    white_ip_group.ips[_] == "0.0.0.0/0"
}

## Kibana 公网开放到 0.0.0.0/0
misconfiguration if {
    some white_ip_group in input.InstanceDetail.networkConfig.whiteIpGroupList
    white_ip_group.whiteIpType == "PUBLIC_KIBANA"
    white_ip_group.ips[_] == "0.0.0.0/0"
}
