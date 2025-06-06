package alb_open_to_pub_without_acl_159
import rego.v1

default risk := false

risk if {
    AlbType == "public"
    count(PublicIp) > 0
    acl_misconfig
}

AlbType := input.ALB.AlbType
PublicIp := input.ALB.PublicIp


## 白名单配置0.0.0.0
acl_misconfig if {
    some acl in input.Listeners[_].Acls[_].LoadBalancerAclEntrySet
    acl.RuleAction == "allow"
    acl.CidrBlock == "0.0.0.0/0"
}

## 未配置acl
acl_misconfig if {
    input.Listeners[_].Acls == null
}