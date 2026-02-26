package aws_iam_role_high_priv_cross_account_assume_without_condition_900043
import rego.v1

default risk := false

risk if {
  high_privilege_role
  cross_account_trust_without_condition(input.Role.AssumeRolePolicyDocument)
}

risk if {
  high_privilege_role
  cross_account_trust_without_condition(urlquery.decode(input.Role.AssumeRolePolicyDocument))
}

messages contains {"Description": "高权限角色允许跨账号主体AssumeRole且无Condition约束。"} if {
  risk
}

high_privilege_role if {
  some p in input.AttachedPolicies
  p.PolicyName in ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess"]
}

high_privilege_role if {
  some d in input.AttachedPolicyDocuments
  document_is_admin(d.Document)
}

high_privilege_role if {
  some d in input.InlinePolicyDocuments
  document_is_admin(d.Document)
}

document_is_admin(doc) if {
  is_array(doc.Statement)
  some st in doc.Statement
  lower(st.Effect) == "allow"
  action_is_admin(st.Action)
  resource_is_all(st.Resource)
}

document_is_admin(doc) if {
  not is_array(doc.Statement)
  st := doc.Statement
  lower(st.Effect) == "allow"
  action_is_admin(st.Action)
  resource_is_all(st.Resource)
}

cross_account_trust_without_condition(doc) if {
  role_account := role_account_id
  role_account != ""
  contains(doc, "\"Condition\"") == false
  some m in regex.find_all_string_submatch_n(`arn:aws[a-z-]*:iam::([0-9]{12}):`, doc, -1)
  count(m) >= 2
  trusted_account := m[1]
  trusted_account != role_account
}

role_account_id := account if {
  arn := input.Role.Arn
  parts := split(arn, ":")
  count(parts) > 4
  account := parts[4]
}

action_is_admin(a) if { action_is_admin_value(a) }
action_is_admin(a) if {
  some x in a
  action_is_admin_value(x)
}

action_is_admin_value(a) if { a == "*" }
action_is_admin_value(a) if { a == "iam:*" }

resource_is_all(r) if { r == "*" }
resource_is_all(r) if {
  some x in r
  x == "*"
}
