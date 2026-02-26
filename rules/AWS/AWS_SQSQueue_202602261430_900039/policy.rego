package aws_sqs_policy_public_access_900039
import rego.v1

default risk := false

risk if {
  p := input.Policy
  p != null
  some s in statements
  effect_allow(s)
  principal_is_wildcard(s.Principal)
  allows_sensitive_sqs_action(s.Action)
}

messages contains {"Description": "SQS队列策略允许任意主体执行敏感消息操作。"} if {
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

allows_sensitive_sqs_action(a) if {
  sensitive_sqs_action_value(a)
}

allows_sensitive_sqs_action(a) if {
  some x in a
  sensitive_sqs_action_value(x)
}

sensitive_sqs_action_value(a) if { a == "sqs:*" }
sensitive_sqs_action_value(a) if { a == "sqs:SendMessage" }
sensitive_sqs_action_value(a) if { a == "sqs:ReceiveMessage" }
sensitive_sqs_action_value(a) if { a == "sqs:DeleteMessage" }
sensitive_sqs_action_value(a) if { a == "*" }
