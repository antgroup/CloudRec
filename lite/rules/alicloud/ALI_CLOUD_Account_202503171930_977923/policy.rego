package root_ak_unused_7200001
import rego.v1

default risk := false
risk if {
	root_with_unused_ak
}

root_with_unused_ak if {
    input.AccountSecurityPracticeReport.AccountSecurityPracticeUserInfo.UnusedAkNum > 0
}