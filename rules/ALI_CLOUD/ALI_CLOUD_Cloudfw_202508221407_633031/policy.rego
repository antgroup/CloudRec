package cloudfw_open_unstandard_port_12200004
import rego.v1
default risk := false

risk if {
    count(open_unstandard_port) > 0
}

standard_ports := {"80","443"}
AclUuid := input.Policy.AclUuid
open_unstandard_port contains port if {
    input.Policy.AclAction == "accept"
    input.Policy.Proto != "ICMP"
    port := input.Policy.DestPort
    not port in standard_ports
}

