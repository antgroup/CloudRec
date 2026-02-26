package aws_rds_public_open_db_port_900008
import rego.v1

default risk := false

risk if {
  input.DBInstance.PubliclyAccessible == true
  db_port_open_to_world
}

messages contains {"Description": "RDS公网可达且数据库端口对公网开放。"} if {
  risk
}

db_port_open_to_world if {
  db_port := to_number(input.DBInstance.Endpoint.Port)
  some sg in input.VPCSecurityGroups
  some perm in sg.IpPermissions
  protocol_match(perm.IpProtocol)
  cidr_world(perm)
  port_match(perm, db_port)
}

protocol_match(p) if { p == "-1" }
protocol_match(p) if { lower(p) == "tcp" }

cidr_world(perm) if {
  some r in perm.IpRanges
  r.CidrIp == "0.0.0.0/0"
}

cidr_world(perm) if {
  some r6 in perm.Ipv6Ranges
  r6.CidrIpv6 == "::/0"
}

port_match(perm, db_port) if {
  perm.FromPort != null
  perm.ToPort != null
  to_number(perm.FromPort) <= db_port
  to_number(perm.ToPort) >= db_port
}
