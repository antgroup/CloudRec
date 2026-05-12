package ram_sso_enabled_2200011
import rego.v1

default risk := false
risk if {
    ram_sso_unabled
}
ram_sso_unabled if {
    input.UserSsoSettings.SsoEnabled != true
}