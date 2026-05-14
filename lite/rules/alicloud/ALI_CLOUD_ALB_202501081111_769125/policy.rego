package alb_open_to_pub_without_acl_2100001
import rego.v1

default risk := false

risk if {
    address_type_is_internet
    acl_misconfig
}

lb_id := input.LoadBalancer.LoadBalancerId
lb_name := input.LoadBalancer.LoadBalancerName
address_type := input.LoadBalancer.AddressType

address_type_is_internet if {
    address_type == "Internet"
}

## 白名单配置0.0.0.0
acl_misconfig if {
    some acl in input.Listeners[_].ListenerAttribute.AclList
    acl.AclType == "White"
    acl.AclEntries[_].Entry == "0.0.0.0/0"
}

## 未配置acl
acl_misconfig if {
    input.Listeners[_].ListenerAttribute.AclList == null
}