package aws_network_acl_admin_ports_open_900034
import rego.v1

default risk := false

risk if {
  some e in input.ACL.Entries
  e.Egress == false
  e.RuleAction == "allow"
  e.CidrBlock == "0.0.0.0/0"
  exposes_admin_port(e)
}

messages contains {"Description": "网络ACL存在22或3389端口公网放通。"} if {
  risk
}

exposes_admin_port(e) if {
  e.Protocol == "-1"
}

exposes_admin_port(e) if {
  e.PortRange.From <= 22
  e.PortRange.To >= 22
}

exposes_admin_port(e) if {
  e.PortRange.From <= 3389
  e.PortRange.To >= 3389
}
