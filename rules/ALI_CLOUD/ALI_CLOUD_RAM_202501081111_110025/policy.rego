package ram_allow_to_login_console_has_ak_2200012

import rego.v1

default risk := false

## 根据下文的检查规则判断是否存在风险
risk if {
	input.ConsoleLogin == true
	input.ExistActiveAccessKey == true
}

user_name := input.UserDetail.UserName
