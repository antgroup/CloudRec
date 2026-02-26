package aws_network_acl_ingress_open_all_900014
import rego.v1

default risk := false

risk if {
  some e in input.ACL.Entries
  e.Egress == false
  e.RuleAction == "allow"
  e.Protocol == "-1"
  e.CidrBlock == "0.0.0.0/0"
}

messages contains {"Description": "网络ACL存在入站All Traffic对0.0.0.0/0放行。"} if {
  risk
}
