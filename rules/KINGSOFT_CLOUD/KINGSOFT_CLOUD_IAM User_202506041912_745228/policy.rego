package example_170

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    MFABindRequired == 0
    ConsoleLogin == true
}

MFABindRequired := input.LoginProfile.EnableMfa
ConsoleLogin := input.LoginProfile.ConsoleLogin