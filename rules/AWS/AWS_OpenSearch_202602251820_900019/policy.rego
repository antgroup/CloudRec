package aws_opensearch_public_wildcard_policy_900019
import rego.v1

default risk := false

risk if {
  is_public_domain
  has_wildcard_principal
}

messages contains {"Description": "公网OpenSearch域访问策略允许任意主体。"} if {
  risk
}

is_public_domain if {
  input.DomainStatus.VPCOptions == null
}

is_public_domain if {
  input.DomainStatus.VPCOptions.SecurityGroupIds == null
}

has_wildcard_principal if {
  p := input.DomainStatus.AccessPolicies
  p != null
  regex.match(`"Principal"\s*:\s*\{[^}]*"AWS"\s*:\s*"\*"`, p)
}

has_wildcard_principal if {
  p := input.DomainStatus.AccessPolicies
  p != null
  regex.match(`"Principal"\s*:\s*"\*"`, p)
}
