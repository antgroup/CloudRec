package aws_iam_access_analyzer_not_enabled_900032
import rego.v1

default risk := false

risk if {
  not has_active_account_analyzer
}

messages contains {"Description": "未发现可用的ACCOUNT类型Access Analyzer。"} if {
  risk
}

has_active_account_analyzer if {
  some a in input.AccessAnalyzers
  a.Status == "ACTIVE"
  a.Type == "ACCOUNT"
}
