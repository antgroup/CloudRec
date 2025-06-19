package example_171

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
## 根据下文的检查规则判断是否存在风险
risk if {
	ak_not_used_for_365_days
    user_not_login_for_365_days
}

now_ns := time.now_ns()
last_login_date := input.LoginProfile.LastLoginDate

## 定义检查规则
aks_of_not_used_for_365_days contains ak_id if {
   some ak_info in input.AccessKeys
   ak_info.Status == "Active"
   last_used_date_ns := time.parse_ns("2006-01-02T15:04:05Z", ak_info.AkLastUsedTime)
   tmp := time.add_date(last_used_date_ns, 0, 0, 365)
   tmp < now_ns
   ak_id := ak_info.AccessKeyId
}

user_not_login_for_365_days if {
    last_login_date != null
    last_used_date_ns := time.parse_ns("2006-01-02T15:04:05Z", last_login_date)
    tmp := time.add_date(last_used_date_ns, 0, 0, 365)
    tmp < now_ns
}

user_not_login_for_365_days if {
    input.LoginProfile == null
}

user_not_login_for_365_days if {
    last_login_date == null
}

ak_not_used_for_365_days if {
    input.AccessKeys == null
} 

ak_not_used_for_365_days if {
    count(aks_of_not_used_for_365_days) = count(input.AccessKeys)
}
