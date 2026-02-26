package aws_iam_user_active_accesskey_900002
import rego.v1

default risk := false

risk if {
  high_privilege_user
  has_active_access_key
}

messages contains {"Description": "高权限IAM用户存在活动AccessKey，建议停用长期密钥并改用临时凭证。"} if {
  risk
}

high_privilege_user if {
  some p in input.AttachedPolicies
  p.PolicyName in ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess"]
}

has_active_access_key if {
  some k in input.AccessKeys
  k.Status == "Active"
}
