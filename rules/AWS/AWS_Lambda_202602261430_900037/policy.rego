package aws_lambda_function_url_anonymous_900037
import rego.v1

default risk := false

risk if {
  some cfg in input.URLConfigs
  lower(sprintf("%v", [cfg.AuthType])) == "none"
}

messages contains {"Description": "Lambda Function URL使用NONE鉴权，允许匿名访问。"} if {
  risk
}
