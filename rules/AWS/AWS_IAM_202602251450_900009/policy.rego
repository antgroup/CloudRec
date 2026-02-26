package aws_iam_role_admin_wildcard_trust_900009
import rego.v1

default risk := false

risk if {
  has_admin_policy
  wildcard_principal_in_doc(input.Role.AssumeRolePolicyDocument)
}

risk if {
  has_admin_policy
  wildcard_principal_in_doc(urlquery.decode(input.Role.AssumeRolePolicyDocument))
}

messages contains {"Description": "高权限角色信任策略过宽，建议收敛Principal范围。"} if {
  risk
}

has_admin_policy if {
  some p in input.AttachedPolicies
  p.PolicyName in ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess"]
}

wildcard_principal_in_doc(doc) if {
  regex.match(`"Principal"\s*:\s*\{[^}]*"AWS"\s*:\s*"\*"`, doc)
}

wildcard_principal_in_doc(doc) if {
  regex.match(`"Principal"\s*:\s*\{[^}]*"Federated"\s*:\s*"\*"`, doc)
}

wildcard_principal_in_doc(doc) if {
  regex.match(`"Principal"\s*:\s*\{[^}]*"Service"\s*:\s*"\*"`, doc)
}
