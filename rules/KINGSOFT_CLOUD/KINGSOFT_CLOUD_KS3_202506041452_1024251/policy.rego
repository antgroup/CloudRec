package example_160

import rego.v1

# Use [input] to get the value from the input data, such as "input.object.field1".

# Use [risk] flag to determine whether it is a risk, When [risk] is true, it is judged as a risk.

default risk = false
risk if {
    LoggingDisable
}

LoggingDisable if {
    input.BucketLogging == null
}

LoggingDisable if {
    input.BucketLogging.LoggingEnabled == null
}

LoggingEnabled :=  input.BucketLogging.LoggingEnabled 