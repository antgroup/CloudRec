package ak_has_not_used_for_365_days_5700001
import rego.v1

default risk := false
risk if {
	count(ak_has_not_used_for_365_days) > 0
}

ram_aks := input.AccessKeys
now_ns := time.now_ns()

## 定义检查规则
ak_has_not_used_for_365_days contains ak_id if {
   some ak_info in ram_aks
   ak_info.AccessKey.Status == "Active"
   last_used_date_ns := time.parse_rfc3339_ns(ak_info.LastUsedDate)
   tmp := time.add_date(last_used_date_ns, 0, 0, 365)
   tmp < now_ns
   ak_id := ak_info.AccessKey.AccessKeyId
}
