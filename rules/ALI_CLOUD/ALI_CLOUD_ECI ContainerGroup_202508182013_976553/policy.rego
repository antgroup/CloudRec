package cloudrec_11900002

import rego.v1

default risk = false

risk if {
    has_internet_ip
    count(security_groups_to_all)>0
    min_priority_with_drop != true
}
messages contains message if {
    risk == true
    message := {
        "Description": "ECI Container Group are exposed",
        "SecurityGroup": input.SecurityGroup
    }
}

has_internet_ip if {
    input.ContainerGroup.InternetIp != ""
}

security_groups_to_all contains p if {
    some p in input.SecurityGroup.Permissions
    p.SourceCidrIp == "0.0.0.0/0"
    p.PortRange in ["1/65535","-1/-1"]
    p.Direction == "ingress"
    p.IpProtocol in ["TCP","ALL"]
}
extract_key_values(input_array, key) = values if {
    values := [v | i := input_array[_]; v := to_number(i[key])]
}

default min_priority_with_drop := false
min_priority_with_drop if {
    some p in security_groups_to_all
    to_number(p.Priority) == min(extract_key_values(security_groups_to_all,"Priority"))
    p.Policy == "Drop"
}