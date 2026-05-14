package cloudrec_2200006

import rego.v1

default risk := false

risk if {
	hasRisk
}

hasRisk if {
	input.Instance.AssetTypeName == "云服务器"
	input.Instance.Status == "Running"
	agent_not_online
}

agent_not_online if {
	lower(sprintf("%v", [client_status])) != "online"
}


AssetTypeName := input.Instance.AssetTypeName

AuthVersionName := input.Instance.AuthVersionName

InstanceId := input.Instance.InstanceId

ClientStatus := input.Instance.ClientStatus

Status := input.Instance.Status

client_status := object.get(object.get(input, "Instance", {}), "ClientStatus", "")
