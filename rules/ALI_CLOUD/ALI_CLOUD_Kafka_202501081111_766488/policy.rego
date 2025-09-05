package kafka_open_to_all_public_3200001
import rego.v1

default risk := false

risk if {
    is_internet_instance
    is_acl_misconfiguraion
}

is_internet_instance if {
    input.InstanceVO.DeployType == 4
}

internet_allowe_ip_list := input.AllowedList.InternetList[_].AllowedIpList

is_acl_misconfiguraion if {
    some acl in internet_allowe_ip_list
    acl == "0.0.0.0/0"
}