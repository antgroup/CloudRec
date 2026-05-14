package cloudrec_9100002

import rego.v1

default risk := false
risk if {
    login_network_masks_is_empty
}
messages contains message if {
    risk == true
    message := {
        "Description": "阿里云未启用控制台登录来源限制"
    }
}

login_network_masks_is_empty if {
    input.SecurityPreference.LoginProfilePreference.LoginNetworkMasks == ""
}