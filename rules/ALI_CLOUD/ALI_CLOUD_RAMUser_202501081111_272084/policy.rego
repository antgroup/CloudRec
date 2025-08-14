package ram_user_with_risk_access_3700001_195

import rego.v1
import data

default risk := false

risk if {
	count(using_high_risk_access) > 0
    not tmp_white
}

high_risk_access_list := ["AliyunRAMFullAccess","AdministratorAccess"]

using_high_risk_access contains p if {
    some policy in input.Policies
    p := policy.Policy.PolicyName
    p in high_risk_access_list
} 


