package aws_ec2_default_sg_allows_traffic_900033
import rego.v1

default risk := false

risk if {
  lower(input.SecurityGroup.GroupName) == "default"
  count(input.SecurityGroup.IpPermissions) > 0
}

risk if {
  lower(input.SecurityGroup.GroupName) == "default"
  some p in input.SecurityGroup.IpPermissionsEgress
  not default_allow_all_egress_only(p)
}

messages contains {"Description": "默认安全组存在放通规则。"} if {
  risk
}

# AWS default SG 默认允许 all egress，这里不作为风险；其他 egress 规则视为风险
default_allow_all_egress_only(p) if {
  p.IpProtocol == "-1"
  p.FromPort == null
  p.ToPort == null
  some r in p.IpRanges
  r.CidrIp == "0.0.0.0/0"
}
