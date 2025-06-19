package example_166

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    expired_or_below_90days
}

now_ns := time.now_ns()
end_date := input.Cert.ExpireTime
end_date_ns := time.parse_ns("2006-01-02 15:04:05", end_date)
diff := time.diff(end_date_ns, now_ns)

## 定义检查规则
expired_or_below_90days if {
    diff[0] = 0 ## 年
    diff[1] < 3 ## 月
}

expired_or_below_90days if {
    input.Cert.CertificateStatus == 8
}

