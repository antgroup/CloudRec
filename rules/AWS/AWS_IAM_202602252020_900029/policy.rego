package aws_iam_access_key_over_90_days_900029
import rego.v1

default risk := false

risk if {
  now_ns := time.now_ns()
  some k in input.AccessKeys
  k.Metadata.Status == "Active"
  create_ns := time.parse_rfc3339_ns(k.Metadata.CreateDate)
  now_ns - create_ns > 90 * 24 * 60 * 60 * 1000000000
}

messages contains {"Description": "存在超过90天未轮换的活动AccessKey。"} if {
  risk
}
