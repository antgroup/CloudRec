package aws_iam_console_user_no_mfa_900013
import rego.v1

default risk := false

risk if {
  input.LoginProfile != null
  count(input.MFADevices) == 0
}

messages contains {"Description": "具备控制台登录能力的IAM用户未开启MFA。"} if {
  risk
}
