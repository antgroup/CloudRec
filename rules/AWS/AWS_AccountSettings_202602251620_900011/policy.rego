package aws_iam_account_password_policy_weak_900011
import rego.v1

default risk := false

risk if {
  to_number(input.PasswordPolicy.MinimumPasswordLength) < 14
}

risk if {
  input.PasswordPolicy.RequireSymbols != true
}

risk if {
  input.PasswordPolicy.RequireNumbers != true
}

risk if {
  input.PasswordPolicy.RequireUppercaseCharacters != true
}

risk if {
  input.PasswordPolicy.RequireLowercaseCharacters != true
}

messages contains {"Description": "IAM账户密码策略强度不足（长度或复杂度要求不达标）。"} if {
  risk
}
