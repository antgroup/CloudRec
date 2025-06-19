package example_169

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false

risk if {
    not is_sso_enabled
    not_enforce_mfa
}

not_enforce_mfa if {
    input.User.EnableMFA != 1
}

is_sso_enabled if {
    input.SsoSettings.Status == 1
}