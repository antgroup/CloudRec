package cloudrec_11800001

import rego.v1

default risk = false

risk if {
    isPublic
}
messages contains message if {
    risk == true
    message := {
        "Description": "ECS Images enabled Public Share"
    }
}

isPublic if {
    input.Image.IsPublic == true
}