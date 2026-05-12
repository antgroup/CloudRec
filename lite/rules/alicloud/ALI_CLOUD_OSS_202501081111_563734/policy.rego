package oss_bucket_anony_access_2200008
import rego.v1

default risk := false

risk if {
	not block_public_access
	input.BucketPolicyStatus.IsPublic == true
}

risk if {
	not block_public_access
	not input.BucketPolicyStatus.IsPublic == false
	count(risk_statements) > 0
}

risk_statements contains statement if {
	some statement in input.BucketPolicy.Statement
	statement.Effect == "Allow"
	public_principal(statement.Principal)
	not restrictive_condition(statement)
}

block_public_access if {
	input.BucketInfo.BlockPublicAccess == true
}

public_principal(principal) if {
	principal == "*"
}

public_principal(principal) if {
	principal[_] == "*"
}

public_principal(principal) if {
	some key
	principal[key][_] == "*"
}

restrictive_condition(statement) if {
	fixed_source_vpc(statement.Condition)
}

restrictive_condition(statement) if {
	fixed_source_ip(statement.Condition)
}

restrictive_condition(statement) if {
	fixed_access_id(statement.Condition)
}

fixed_source_vpc(condition) if {
	value := condition_values(condition, "acs:SourceVpc")[_]
	startswith(lower(value), "vpc-")
	not contains(value, "*")
}

fixed_source_vpc(condition) if {
	value := condition_values(condition, "acs:SourceVpcId")[_]
	startswith(lower(value), "vpc-")
	not contains(value, "*")
}

fixed_access_id(condition) if {
	value := condition_values(condition, "acs:AccessId")[_]
	value != ""
	value != "*"
	not contains(value, "*")
}

fixed_source_ip(condition) if {
	value := condition_values(condition, "acs:SourceIp")[_]
	prefix := cidr_prefix(value)
	not contains(value, ":")
	prefix >= 8
}

fixed_source_ip(condition) if {
	value := condition_values(condition, "acs:SourceIp")[_]
	prefix := cidr_prefix(value)
	contains(value, ":")
	prefix >= 32
}

fixed_source_ip(condition) if {
	value := condition_values(condition, "acs:SourceIp")[_]
	not contains(value, "/")
	not contains(value, "*")
	value != ""
}

condition_values(condition, condition_key) := values if {
	values := [value |
	some operator
	raw := condition[operator][condition_key]
	value := list_values(raw)[_]
	]
}

list_values(raw) := raw if {
	is_array(raw)
}

list_values(raw) := [raw] if {
	not is_array(raw)
}

cidr_prefix(value) := prefix if {
	parts := split(value, "/")
	count(parts) == 2
	prefix := to_number(parts[1])
}

BucketName := input.BucketProperties.Name
