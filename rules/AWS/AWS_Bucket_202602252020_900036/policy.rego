package aws_s3_bucket_ssl_not_enforced_900036
import rego.v1

default risk := false

risk if {
  p := input.Policy
  p == null
}

risk if {
  p := input.Policy
  p != null
  not has_ssl_enforcement_statement
}

messages contains {"Description": "S3 Bucket策略未强制SSL访问。"} if {
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

has_ssl_enforcement_statement if {
  some s in statements
  lower(s.Effect) == "deny"
  secure_transport_false(s)
}

secure_transport_false(s) if {
  s.Condition.Bool["aws:SecureTransport"] == "false"
}

secure_transport_false(s) if {
  s.Condition.Bool["aws:SecureTransport"] == false
}
