package aws_clb_internet_facing_risky_listener_900007
import rego.v1

default risk := false

high_risk_ports := {22, 3389, 3306, 5432, 6379, 27017}

risk if {
  input.LoadBalancer.Scheme == "internet-facing"
  some ld in input.LoadBalancer.ListenerDescriptions
  to_number(ld.Listener.LoadBalancerPort) in high_risk_ports
}

messages contains {"Description": "公网CLB监听高危端口，建议仅开放必要业务端口。"} if {
  risk
}
