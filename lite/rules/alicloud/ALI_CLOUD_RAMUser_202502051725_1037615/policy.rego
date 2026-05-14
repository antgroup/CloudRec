package user_not_using_for_365_days_5700002
import rego.v1

default risk := false
## 根据下文的检查规则判断是否存在风险
risk if {
	count(ak_not_using_for_365_days) == count(ram_aks)
    user_not_login_for_365_days
}

ram_aks := input.AccessKeys
now_ns := time.now_ns()
last_login_date := input.UserDetail.LastLoginDate

## 定义检查规则
ak_not_using_for_365_days contains ak_id if {
   some ak_info in ram_aks
   ak_info.AccessKey.Status == "Active"
   last_used_date_ns := time.parse_rfc3339_ns(ak_info.LastUsedDate)
   tmp := time.add_date(last_used_date_ns, 0, 0, 365)
   tmp < now_ns
   ak_id := ak_info.AccessKey.AccessKeyId
}

user_not_login_for_365_days if {
    last_login_date != ""
    last_used_date_ns := time.parse_rfc3339_ns(last_login_date)
    tmp := time.add_date(last_used_date_ns, 0, 0, 365)
    tmp < now_ns
}

user_name := input.UserDetail.UserName