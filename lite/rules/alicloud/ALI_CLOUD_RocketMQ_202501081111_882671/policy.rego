package cloudrec_3900001
import rego.v1

default risk := false

risk if {
	enable_internet
    ip_white_list_misconfig
}

enable_internet if {
    input.Instance.networkInfo.internetInfo.internetSpec == "enable"
}

ip_white_list_misconfig if {
    ip_white_list := input.WhiteList
    ip_white_list == null
}
ip_white_list_misconfig if {
    ip_white_list := input.WhiteList
    "0.0.0.0/0" in ip_white_list
}