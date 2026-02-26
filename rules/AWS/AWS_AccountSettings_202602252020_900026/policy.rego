package aws_iam_root_mfa_not_enabled_900026
import rego.v1

default risk := false

risk if {
  to_number(input.AccountSummary.AccountMFAEnabled) != 1
}

messages contains {"Description": "Root账号未启用MFA。"} if {
  risk
}
