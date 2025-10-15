package hws_root_account_has_ak_1

import rego.v1

default risk := false

risk if {
    count(root_ak) != 0
}

root_ak contains p if {
    input.Credentials != null
    some p in input.Credentials
    p.access != null
    p.status == "active"
    input.UserAttribute.is_domain_owner == true
    }
