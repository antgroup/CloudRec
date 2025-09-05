package oss_bucket_anony_access_2200008
import rego.v1

default risk := false

risk if {
	count(risk_statements) > 0
}

risk_statements contains statement if {
	some i, statement in input.BucketPolicy.Statement
	statement.Effect == "Allow"
	statement.Principal == ["*"]
	not statement.Condition
}

BucketName := input.BucketProperties.Name