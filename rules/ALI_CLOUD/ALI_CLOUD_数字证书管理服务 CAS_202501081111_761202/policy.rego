package cloudrec_2200013

import rego.v1

default risk := false

## 根据下文的检查规则判断是否存在风险
risk if {
    end_date_below_90_days
}

now_ns := time.now_ns()
end_date := input.CertificateOrder.EndDate
end_date_ns := time.parse_ns("2006-01-02", end_date)
diff := time.diff(end_date_ns, now_ns)

## 定义检查规则
end_date_below_90_days if {
    diff[0] = 0 ## 年
    diff[1] < 3 ## 月
}
