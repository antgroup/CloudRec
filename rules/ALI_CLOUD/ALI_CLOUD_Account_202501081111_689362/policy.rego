package cloudrec_3800002
import rego.v1

default risk := false
risk if {
	root_with_accessKey
}
messages contains message if {
    risk == true
    message := {
        "Description": sprintf("该账号启用了主账号AccessKey, 数量为 %v", [root_ak_num]),
    }
}

root_with_accessKey if {
    input.AccountSecurityPracticeReport.AccountSecurityPracticeUserInfo.RootWithAccessKey > 0
}
root_ak_num := input.AccountSecurityPracticeReport.AccountSecurityPracticeUserInfo.RootWithAccessKey