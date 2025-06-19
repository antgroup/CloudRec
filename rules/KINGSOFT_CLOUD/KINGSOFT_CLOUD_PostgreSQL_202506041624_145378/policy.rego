package example_162

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false

risk if {
    Audit == true
}

Audit := input.Instance.Audit