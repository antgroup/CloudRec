package cloudrec_7800003
import rego.v1

default risk := false
risk if {
    is_internet
    count(unprotected_by_waf) > 0
}
# messages will be shown if risk is true
messages contains message if {
    risk == true
    message := {
        "Description": "here are the listeners unprotected_by_waf",
        "result": unprotected_by_waf
    }
}

is_internet if {
    input.LoadBalancerAttribute.AddressType == "internet"
}

listener_infos contains listener_info if {
    some ListenerPortAndProtocal in input.LoadBalancerAttribute.ListenerPortsAndProtocal.ListenerPortAndProtocal
    listener_info := {
        "instanceId": input.LoadBalancerAttribute.LoadBalancerId,
        "port": ListenerPortAndProtocal.ListenerPort,
        "protocal": ListenerPortAndProtocal.ListenerProtocal
    }
}

unprotected_by_waf contains listener_info if {
    some listener_info in listener_infos
    not listener_protected(listener_info)
}

listener_protected(listener) if {
    some resource in input.WAFDetail.Resources
    detail := resource.Resource.Detail
    listener.instanceId == detail.instanceId
    listener.protocal == detail.protocol
    listener.port == detail.port
}