package example_164

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    neverLogin
}

LoginProfile := input.LoginProfile

neverLogin if {
    LoginProfile.LastLoginDate == null
}

neverLogin if {
    LoginProfile == null
}