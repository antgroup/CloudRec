package root_user_bind_mfa_6500001
import rego.v1

default risk := false
risk if {
    not is_sso_enabled
    not is_mfa_binded
}

is_sso_enabled if {
    input.UserSsoSettings.SsoEnabled == true
}

is_mfa_binded if {
    input.AccountSecurityPracticeReport.AccountSecurityPracticeUserInfo.BindMfa == true
}