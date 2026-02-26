package aws_vpc_endpoint_service_wildcard_principal_900016
import rego.v1

default risk := false

risk if {
  some p in input.AllowedPrincipals
  p.Principal == "*"
}

messages contains {"Description": "VPC Endpoint Service权限允许任意主体。"} if {
  risk
}
