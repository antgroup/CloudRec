package lindorm_exposed_to_pub_3800005
import rego.v1

default risk := false

risk if {
	has_public_address
    acl_open_to_all_pub
}

has_public_address if {
    some engine in input.EngineList
    engine.NetInfoList[_].NetType == "0"
}

acl_open_to_all_pub if {
    "0.0.0.0/0" in input.InstanceIpWhiteList.IpList
}
