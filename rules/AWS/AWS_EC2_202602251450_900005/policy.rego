package aws_ec2_sg_risky_ports_open_900005
import rego.v1

default risk := false

high_risk_ports := {22, 3389, 3306, 5432, 6379, 27017}

risk if {
  some perm in input.SecurityGroup.IpPermissions
  some r in perm.IpRanges
  r.CidrIp == "0.0.0.0/0"
  port_exposed(perm)
}

messages contains {"Description": "安全组高危端口对0.0.0.0/0开放。"} if {
  risk
}

port_exposed(perm) if {
  to_number(perm.FromPort) in high_risk_ports
}

port_exposed(perm) if {
  to_number(perm.ToPort) in high_risk_ports
}
