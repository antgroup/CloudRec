package aws_iam_policy_admin_wildcard_900031
import rego.v1

default risk := false

risk if {
  doc := urlquery.decode(input.Version.Document)
  has_allow_all_action(doc)
  has_allow_all_resource(doc)
}

messages contains {"Description": "自定义IAM策略存在管理员全权授权。"} if {
  risk
}

has_allow_all_action(doc) if {
  regex.match(`"Action"\s*:\s*"\*"`, doc)
}

has_allow_all_action(doc) if {
  regex.match(`"Action"\s*:\s*\[[^\]]*"\*"`, doc)
}

has_allow_all_resource(doc) if {
  regex.match(`"Resource"\s*:\s*"\*"`, doc)
}

has_allow_all_resource(doc) if {
  regex.match(`"Resource"\s*:\s*\[[^\]]*"\*"`, doc)
}
