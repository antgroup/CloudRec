package hws_iam_ak_not_change_2

import rego.v1

default risk := false

risk if {
    count(iam_ak_not_change) != 0
}

iam_ak_not_change contains p if {
    input.Credentials != null
    some p in input.Credentials
    p.access != null
    p.status == "active"
    create_time_ns := time.parse_rfc3339_ns(p.create_time)
    time.now_ns() - create_time_ns >= 90 * 24 * 60 * 60 * 1000000000
    }
