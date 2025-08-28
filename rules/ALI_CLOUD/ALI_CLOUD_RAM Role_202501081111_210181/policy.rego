package other_account_assume_role_3600012

import rego.v1

default risk := false

risk if {
	count(other_account_assume_role) > 0
}

assume_role_policies := json.unmarshal(input.Role.AssumeRolePolicyDocument)

my_account := split(input.Role.Arn,":")[3]

other_account_assume_role contains account if {
    some statement in assume_role_policies.Statement
    statement.Action == "sts:AssumeRole"
    statement.Effect == "Allow"
    some ram in statement.Principal.RAM
    account := split(ram,":")[3]
    account != my_account
    
}

role_name := input.Role.RoleName