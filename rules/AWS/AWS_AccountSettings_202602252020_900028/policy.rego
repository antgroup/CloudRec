package aws_iam_password_reuse_not_prevented_900028
import rego.v1

default risk := false

risk if {
  input.PasswordPolicy.PasswordReusePrevention == null
}

risk if {
  to_number(input.PasswordPolicy.PasswordReusePrevention) < 1
}

messages contains {"Description": "IAM密码策略未配置密码复用防护。"} if {
  risk
}
