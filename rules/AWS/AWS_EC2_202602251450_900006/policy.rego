package aws_ec2_public_instance_risky_sg_900006
import rego.v1

default risk := false

high_risk_ports := {22, 3389, 3306, 5432, 6379, 27017}

risk if {
  has_public_ip
  some sgd in input.SecurityGroups
  some perm in sgd.SecurityGroup.IpPermissions
  some r in perm.IpRanges
  r.CidrIp == "0.0.0.0/0"
  risky(perm)
}

messages contains {"Description": "公网实例关联安全组存在高危端口公网放行。"} if {
  risk
}

has_public_ip if {
  input.Instance.PublicIpAddress != null
  input.Instance.PublicIpAddress != ""
}

risky(perm) if { to_number(perm.FromPort) in high_risk_ports }
risky(perm) if { to_number(perm.ToPort) in high_risk_ports }
