package cloudrec_12000002

import rego.v1

default risk = false

risk if {
    http_trigger_internet_anonymous
}
messages contains message if {
    risk == true
    message := {
        "Description": "Internet HTTP Trigger using 'anonymous' auth type",
    }
}

http_trigger_internet_anonymous if {
    some t in input.Triggers
    t.triggerType == "http"
    config := json.unmarshal(t.triggerConfig)
    config.authType == "anonymous"
    config.disableURLInternet == false
}
