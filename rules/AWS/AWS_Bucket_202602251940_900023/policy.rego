package aws_s3_bucket_public_policy_900023
import rego.v1

default risk := false

risk if {
  p := input.Policy
  p != null
  some s in statements
  principal_is_wildcard(s.Principal)
  effect_allow(s)
  allows_public_read(s.Action)
}

messages contains {"Description": "S3 Bucket策略存在公开读取权限。"} if {
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

allows_public_read(a) if {
  a == "s3:*"
}

allows_public_read(a) if {
  a == "s3:GetObject"
}

allows_public_read(a) if {
  some x in a
  x == "s3:*"
}

allows_public_read(a) if {
  some x in a
  x == "s3:GetObject"
}
