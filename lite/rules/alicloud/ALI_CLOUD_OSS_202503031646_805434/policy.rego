package cloudrec_6500008
import rego.v1

default risk := false
risk if {
    input.LoggingEnabled == null
}
messages contains message if {
    risk == true
    message := {
        "Decription": "OSS Bucket should enable Logging"
    }
}