package aws_iam_user_inlinepolicy_no_mfa_900004
import rego.v1

default risk := false

risk if {
  count(input.InlinePolicies) > 0
  count(input.MFADevices) == 0
}

messages contains {"Description": "存在InlinePolicy的IAM用户未开启MFA，建议开启MFA并复核内联权限。"} if {
  risk
}
