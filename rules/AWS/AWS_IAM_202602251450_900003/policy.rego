package aws_iam_role_wildcard_principal_900003
import rego.v1

default risk := false

risk if {
  wildcard_principal_in_doc(input.Role.AssumeRolePolicyDocument)
}

risk if {
  wildcard_principal_in_doc(urlquery.decode(input.Role.AssumeRolePolicyDocument))
}

messages contains {"Description": "IAM Role信任策略存在通配符Principal，建议限定可信主体。"} if {
  risk
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
