package aws_iam_user_no_mfa_900001
import rego.v1

default risk := false

risk if {
    high_privilege_user
    mfa_not_enabled
}

messages contains message if {
    risk
    message := {
        "Description": "高权限IAM用户未开启MFA，建议立即开启MFA并限制长期凭证使用。"
    }
}

high_privilege_user if {
    some p in input.AttachedPolicies
    p.PolicyName in ["AdministratorAccess", "PowerUserAccess", "IAMFullAccess"]
}

mfa_not_enabled if {
    count(input.MFADevices) == 0
}
