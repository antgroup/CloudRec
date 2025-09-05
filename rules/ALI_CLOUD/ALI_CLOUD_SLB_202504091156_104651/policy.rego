package cloudrec_7900001
import rego.v1
import data

default risk = false
risk if {
    count(misconfig_acl) > 0
    is_internet_slb
}
messages contains message if {
    risk == true
    message := {
        "Description": "here is the info about the misconfigration of listeners and acls",
        "result": misconfig_acl
    }
}

is_internet_slb if {
    input.LoadBalancer.AddressType == "internet"
}

misconfig_acl contains misconfigration if {
    some l in input.Listeners
    some acl in l.AclList[_].AclEntrys[_]
    acl_ip := acl.AclEntryIP
    acl_ip_is_special_purpose_address(acl_ip) == false
    parts := split(acl_ip , "/")
	size := to_number(parts[1])
	size <= 8
    
    misconfigration := {
        "ListenerPort": l.Listener.ListenerPort,
        "ListenerProtocol": l.Listener.ListenerProtocol,
        "MisconfigrationACL" : acl
    }
}

acl_ip_is_special_purpose_address(acl_ip) := true if {
    count(net.cidr_contains_matches(data.special_purpose_cidr.cidr_list, acl_ip)) > 0
}else := false
