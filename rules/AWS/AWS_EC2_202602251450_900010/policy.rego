package aws_ec2_sg_all_traffic_world_900010
import rego.v1

default risk := false

risk if {
  some perm in input.SecurityGroup.IpPermissions
  perm.IpProtocol == "-1"
  some r in perm.IpRanges
  r.CidrIp == "0.0.0.0/0"
}

messages contains {"Description": "安全组存在全流量对公网开放。"} if {
  risk
}
