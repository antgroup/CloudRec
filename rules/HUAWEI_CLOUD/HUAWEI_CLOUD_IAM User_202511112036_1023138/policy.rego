package hws_ak_no_use_for_one_year_109
import rego.v1

now_ns := time.now_ns()

default risk := false

risk if {
	count(ak_no_use_for_one_year) > 0
}

user_name := input.UserAttribute.name
user_id := input.UserAttribute.domain_id

ak_no_use_for_one_year contains p if {
    some p in input.CredentialsDetail
    p.status == "active"
    last_used_date_ns := time.parse_rfc3339_ns(p.last_use_time)
    tmp := time.add_date(last_used_date_ns, 0, 0, 365)
   	tmp < now_ns
}
