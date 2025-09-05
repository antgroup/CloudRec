package cloudrec_2200006

import rego.v1

default risk := false

risk if {
	hasRisk
}

# The edition of Security Center that is authorized to scan the asset. Valid values:
#
# 	- **1**: Basic edition
#
# 	- **6**: Anti-virus edition
#
# 	- **5**: Advanced edition
#
# 	- **3**: Enterprise edition
#
# 	- **7**: Ultimate edition
#
# 	- **10**: Value-added Plan edition
#
hasRisk if {
	input.Instance.AssetTypeName == "云服务器"
	input.Instance.Status == "Running"
	input.Instance.AuthVersion != 7
}

hasRisk if {
	input.Instance.AssetTypeName == "云服务器"
	input.Instance.Status == "Running"
	input.Instance.ClientStatus == "offline"
}


AssetTypeName := input.Instance.AssetTypeName

AuthVersionName := input.Instance.AuthVersionName

InstanceId := input.Instance.InstanceId

ClientStatus := input.Instance.ClientStatus

Status := input.Instance.Status
