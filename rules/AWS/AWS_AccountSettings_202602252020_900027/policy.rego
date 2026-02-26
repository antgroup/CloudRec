package aws_iam_root_hardware_mfa_not_enabled_900027
import rego.v1

default risk := false

risk if {
  to_number(object.get(input.AccountSummary, "AccountHardwareMFAEnabled", 0)) != 1
}

messages contains {"Description": "Root账号未启用硬件MFA。"} if {
  risk
}
