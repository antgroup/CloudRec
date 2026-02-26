package aws_sns_topic_policy_public_access_900040
import rego.v1

default risk := false

risk if {
  p := input.Policy
  p != null
  some s in statements
  effect_allow(s)
  principal_is_wildcard(s.Principal)
  allows_sensitive_sns_action(s.Action)
}

messages contains {"Description": "SNS Topic策略允许任意主体发布或订阅。"} if {
  risk
}

policy_obj := input.Policy

statements contains s if {
  is_array(policy_obj.Statement)
  some s in policy_obj.Statement
}

statements contains policy_obj.Statement if {
  not is_array(policy_obj.Statement)
}

effect_allow(s) if {
  lower(s.Effect) == "allow"
}

principal_is_wildcard(p) if {
  p == "*"
}

principal_is_wildcard(p) if {
  p.AWS == "*"
}

principal_is_wildcard(p) if {
  some x in p.AWS
  x == "*"
}

allows_sensitive_sns_action(a) if {
  sensitive_sns_action_value(a)
}

allows_sensitive_sns_action(a) if {
  some x in a
  sensitive_sns_action_value(x)
}

sensitive_sns_action_value(a) if { a == "sns:*" }
sensitive_sns_action_value(a) if { a == "sns:Publish" }
sensitive_sns_action_value(a) if { a == "sns:Subscribe" }
sensitive_sns_action_value(a) if { a == "*" }
