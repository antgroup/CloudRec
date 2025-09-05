package cloudrec_12000001

import rego.v1

default risk = false

risk if {
   is_internet
   ForwardTableEntry_is_not_null
}
messages contains message if {
    risk == true
    message := {
        "Description": "NAT Gateway enabled DNAT TableEntry, making internal ip exposed.",
    }
}

is_internet if {
    input.NatGateway.NetworkType == "internet"
}
ForwardTableEntry_is_not_null if {
    input.ForwardTableEntry != null
}