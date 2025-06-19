package example_175

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    count(ak_never_used_after_being_created_90days) > 0
}

now_ns := time.now_ns()

ak_never_used_after_being_created_90days contains ak_info if {
   some ak_info in input.AccessKeys
   ak_info.Status == "Active"
   empty_date(ak_info.AkLastUsedTime)

   create_date_ns := time.parse_ns("2006-01-02T15:04:05Z", ak_info.CreateDate)
   tmp := time.add_date(create_date_ns, 0, 0, 90)
   tmp < now_ns
}

empty_date(str) if {
    str == ""
} else if {
    str == "N/A"
}