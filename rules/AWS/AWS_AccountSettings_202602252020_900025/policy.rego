package aws_iam_root_access_key_exists_900025
import rego.v1

default risk := false

risk if {
  to_number(input.AccountSummary.AccountAccessKeysPresent) > 0
}

messages contains {"Description": "Root账号存在AccessKey。"} if {
  risk
}
