package example_157

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    count(ListenerWithUnsafeProtocal) > 0
}

SlbType := input.SLB.Type
PublicIp := input.SLB.PublicIp

unsafe_protocal := {"HTTP", "TCP", "UDP"}

ListenerWithUnsafeProtocal contains listener if {
    some l in input.Listeners
    l.Listener.ListenerProtocol in unsafe_protocal
    
    listener := l.Listener
}