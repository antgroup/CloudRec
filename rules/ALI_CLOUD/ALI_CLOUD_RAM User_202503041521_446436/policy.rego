package ram_user_never_used_6600001_187
import rego.v1

default risk := false
risk if {
    neverLogin
    noAccessKey
}

neverLogin if {
    input.User.LastLoginDate == ""
    input.UserDetail.LastLoginDate == ""
}

noAccessKey if {
    input.ExistActiveAccessKey != true
}