package example_172

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
	count(ak_has_not_used_for_365_days) > 0
}

aks := input.AccessKeys
now_ns := time.now_ns()

## 定义检查规则
ak_has_not_used_for_365_days contains ak_id if {
   some ak_info in aks
   ak_info.Status == "Active"
   last_used_date_ns := time.parse_ns("2006-01-02T15:04:05Z", ak_info.AkLastUsedTime)
   tmp := time.add_date(last_used_date_ns, 0, 0, 365)
   tmp < now_ns
   ak_id := ak_info.AccessKeyId
}
