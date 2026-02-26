package aws_efs_policy_wildcard_principal_900021
import rego.v1

default risk := false

risk if {
  p := input.FileSystemPolicy
  p != null
  policy_text := json.marshal(p)
  regex.match(`"Effect"\s*:\s*"Allow"`, policy_text)
  has_wildcard_principal(policy_text)
}

messages contains {"Description": "EFS文件系统策略允许任意主体访问。"} if {
  risk
}

has_wildcard_principal(policy_text) if {
  regex.match(`"Principal"\s*:\s*"\*"`, policy_text)
}

has_wildcard_principal(policy_text) if {
  regex.match(`"Principal"\s*:\s*\{[^}]*"AWS"\s*:\s*"\*"`, policy_text)
}
