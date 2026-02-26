package aws_iam_policy_passrole_wildcard_without_condition_900045
import rego.v1

default risk := false

risk if {
  doc := policy_doc(input.Version.Document)
  has_risky_passrole_statement(doc)
}

risk if {
  decoded := urlquery.decode(input.Version.Document)
  doc := policy_doc(decoded)
  has_risky_passrole_statement(doc)
}

messages contains {"Description": "IAM策略存在PassRole到任意资源且无Condition约束。"} if {
  risk
}

policy_doc(raw) := doc if {
  doc := json.unmarshal(raw)
}

has_risky_passrole_statement(doc) if {
  is_array(doc.Statement)
  some st in doc.Statement
  effect_allow(st)
  action_has_passrole(st.Action)
  resource_is_all(st.Resource)
  condition_missing(st)
}

has_risky_passrole_statement(doc) if {
  not is_array(doc.Statement)
  st := doc.Statement
  effect_allow(st)
  action_has_passrole(st.Action)
  resource_is_all(st.Resource)
  condition_missing(st)
}

effect_allow(st) if {
  lower(st.Effect) == "allow"
}

action_has_passrole(a) if {
  action_has_passrole_value(a)
}

action_has_passrole(a) if {
  some x in a
  action_has_passrole_value(x)
}

action_has_passrole_value(a) if { lower(a) == "iam:passrole" }
action_has_passrole_value(a) if { lower(a) == "iam:*" }
action_has_passrole_value(a) if { a == "*" }

resource_is_all(r) if {
  r == "*"
}

resource_is_all(r) if {
  some x in r
  x == "*"
}

condition_missing(st) if {
  st.Condition == null
}

condition_missing(st) if {
  not st.Condition
}
