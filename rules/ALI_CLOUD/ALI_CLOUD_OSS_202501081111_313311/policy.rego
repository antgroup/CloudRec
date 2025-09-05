package oss_could_be_accessed_from_any_vpc_3000001
import rego.v1

default risk := false

risk if {
	count(risk_statements) > 0
}

risk_statements contains statement if {
	some i, statement in input.BucketPolicy.Statement
	statement.Effect == "Allow"
	statement.Principal == ["*"]
	statement.Condition.StringLike["acs:SourceVpc"][_] == "vpc-*"
}

risk_statements contains statement if {
	some i, statement in input.BucketPolicy.Statement
	statement.Effect == "Deny"
	statement.Principal == ["*"]
	statement.Condition.StringNotLike["acs:SourceVpc"][_] == "vpc-*"
	not statement.Condition.NotIpAddress
}
