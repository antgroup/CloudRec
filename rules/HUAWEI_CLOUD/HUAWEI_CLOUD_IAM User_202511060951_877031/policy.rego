package hws_console_account_disable_mfa_39
import rego.v1

default risk := false
default login_without_mfa_rule := false

risk if {
	login_without_mfa_rule
}

user_name := input.UserAttribute.name
user_id := input.UserAttribute.domain_id

login_without_mfa_rule if {
    input.UserAttribute.access_mode == "console"
    input.LoginProtects == null
}