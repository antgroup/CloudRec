package nlb_exposed_high_risk_port_to_pub_3800004
import rego.v1

default risk := false
risk if {
	is_internet_network
    count(listener_open_high_risk_port) > count(min_priority_with_drop)
}
risk if {
    is_internet_network
    count(listener_open_high_risk_port) > 0
    input.SecurityGroups == null
}

is_internet_network if {
    input.LoadBalancer.AddressType == "Internet"
}

servicePorts := data.risk_default_ports.servicePorts
listener_open_high_risk_port contains port if {
    some servicePort in servicePorts
    port := servicePort.port
    port == input.Listeners[_].ServerGroupServers[_].Port
}

sg_with_risk_ports contains {servicePort:p} if {
    some p in input.SecurityGroups[_].Permissions
    parts := split(p.PortRange, "/")
    some servicePort in servicePorts
    servicePort.port in numbers.range(to_number(parts[0]),to_number(parts[1]))
    p.SourceCidrIp == "0.0.0.0/0"
    p.Direction == "ingress"
}

min_priority_with_drop contains p if {
    some servicePort in object.keys(servicePorts)
    sg_with_risk_port := extract_key_values(sg_with_risk_ports, servicePort)
    some p in sg_with_risk_port
    to_number(p.Priority) == min(extract_key_values_to_number(sg_with_risk_port,"Priority"))
    p.Policy == "Drop" 
}

extract_key_values(input_array, key) = values if {
    values := [v | i := input_array[_]; v := i[key]]
}

extract_key_values_to_number(input_array, key) = values if {
    values := [v | i := input_array[_]; v := to_number(i[key])]
}