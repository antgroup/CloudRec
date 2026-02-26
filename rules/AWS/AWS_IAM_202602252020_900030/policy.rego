package aws_iam_unused_credentials_over_45_days_900030
import rego.v1

default risk := false

risk if {
  password_unused_over_45_days
}

risk if {
  active_access_key_unused_over_45_days
}

messages contains {"Description": "存在45天以上未使用的登录凭证。"} if {
  risk
}

password_unused_over_45_days if {
  input.User.PasswordLastUsed != null
  now_ns := time.now_ns()
  last_used_ns := time.parse_rfc3339_ns(input.User.PasswordLastUsed)
  now_ns - last_used_ns > 45 * 24 * 60 * 60 * 1000000000
}

active_access_key_unused_over_45_days if {
  now_ns := time.now_ns()
  some k in input.AccessKeys
  k.Metadata.Status == "Active"
  k.LastUsed.LastUsedDate != null
  last_used_ns := time.parse_rfc3339_ns(k.LastUsed.LastUsedDate)
  now_ns - last_used_ns > 45 * 24 * 60 * 60 * 1000000000
}
