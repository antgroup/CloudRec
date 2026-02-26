package aws_iam_account_password_change_not_allowed_900012
import rego.v1

default risk := false

risk if {
  input.PasswordPolicy.AllowUsersToChangePassword != true
}

messages contains {"Description": "IAM账户未允许用户自行修改密码。"} if {
  risk
}
