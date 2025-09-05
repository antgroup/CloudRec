package ecs_assume_role_3600011

import rego.v1

default risk := false

risk if {
	ecs_assume_role
}

assume_role_policies := json.unmarshal(input.Role.AssumeRolePolicyDocument)

ecs_assume_role if {
    some statement in assume_role_policies.Statement
    statement.Action == "sts:AssumeRole"
    statement.Effect == "Allow"
    "ecs.aliyuncs.com" in statement.Principal.Service
}