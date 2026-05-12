package cloudrec_8600001

import rego.v1

default risk := false

risk if {
	sso_disabled
	bad_policy
}

messages contains message if {
	risk == true
	message := {
		"Description": "阿里云密码复杂度要求"
	}
}

sso_disabled if {
	input.UserSsoSettings.SsoEnabled == false
}

bad_policy if {
	input.PasswordPolicy.MinimumPasswordLength < 10
}
bad_policy if {
	input.PasswordPolicy.RequireLowercaseCharacters == false
}
bad_policy if {
	input.PasswordPolicy.RequireUppercaseCharacters == false
}
bad_policy if {
	input.PasswordPolicy.RequireSymbols == false
}
bad_policy if {
	input.PasswordPolicy.HardExpire == false
}
bad_policy if {
	input.PasswordPolicy.MaxLoginAttemps > 5
}
bad_policy if {
	input.PasswordPolicy.MaxLoginAttemps == 0
}
bad_policy if {
	input.PasswordPolicy.MaxPasswordAge > 180
}
bad_policy if {
	input.PasswordPolicy.MaxPasswordAge == 0
}
bad_policy if {
	input.PasswordPolicy.PasswordReusePrevention < 3
}