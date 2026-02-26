package aws_elbv2_internet_http_listener_900015
import rego.v1

default risk := false

risk if {
  input.ELB.Scheme == "internet-facing"
  some l in input.Listeners
  l.Protocol == "HTTP"
}

messages contains {"Description": "公网ELB存在HTTP明文监听。"} if {
  risk
}
