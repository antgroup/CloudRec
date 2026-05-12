package cloudrec_9100003

import rego.v1

default risk = false

risk if {
    not is_sso_enabled
    not_enforce_mfa
}
messages contains message if {
    risk == true
    message := {
        "Description": "账号登录控制台应启用MFA设备"
    }
}

not_enforce_mfa if {
    input.SecurityPreference.LoginProfilePreference.MFAOperationForLogin != "mandatory"
}

is_sso_enabled if {
    input.UserSsoSettings.SsoEnabled == true
}