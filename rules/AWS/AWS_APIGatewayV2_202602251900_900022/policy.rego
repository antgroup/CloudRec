package aws_apigatewayv2_no_authorizer_exposed_900022
import rego.v1

default risk := false

risk if {
  execute_endpoint_enabled
  count(input.Authorizers) == 0
}

messages contains {"Description": "API默认执行端点开放且未配置Authorizer。"} if {
  risk
}

execute_endpoint_enabled if {
  input.API.DisableExecuteApiEndpoint == null
}

execute_endpoint_enabled if {
  input.API.DisableExecuteApiEndpoint == false
}
