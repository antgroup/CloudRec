package cloudrec_2200013

import rego.v1

default risk := false

## 根据下文的检查规则判断是否存在风险
risk if {
    certificate_expired_or_expires_within_90_days
}

end_date := input.CertificateOrder.EndDate
end_date_ns := time.parse_ns("2006-01-02", end_date)
remaining_ns := end_date_ns - current_time_ns
ninety_days_ns := 90 * 24 * 60 * 60 * 1000000000

current_time_ns := parsed if {
    now_date := object.get(input, "NowDate", "")
    now_date != ""
    parsed := time.parse_ns("2006-01-02", now_date)
} else := time.now_ns()

## 定义检查规则
certificate_expired_or_expires_within_90_days if {
    remaining_ns <= ninety_days_ns
}
