package cloudrec_11900001
import rego.v1

default risk := false

risk if {
    count(risk_statements) > 0
}
messages contains message if {
	risk == true
	message := {
		"Description": "SLS Project Policy 设置为可匿名访问",
		"Policy": policy,
	}
}

policy := json.unmarshal(input.PolicyStatus.body)
risk_statements contains statement if {
	some statement in policy
	statement.Effect == "Allow"
	statement.Principal == ["*"]
	not statement.Condition
}