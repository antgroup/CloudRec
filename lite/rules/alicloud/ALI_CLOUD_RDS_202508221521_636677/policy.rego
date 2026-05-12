package rds_ssl_encryption_12200005
import rego.v1

default risk := false

risk if {
	ssl_enabled == null
}

risk if {
	ssl_enabled == ""
}

risk if {
	lower(sprintf("%v", [ssl_enabled])) == "no"
}

DBInstanceID := input.DBInstanceAttribute.DBInstanceId
SSLStatus := input.DBInstanceSSL.SSLEnabled
ssl_enabled := object.get(object.get(input, "DBInstanceSSL", {}), "SSLEnabled", "")
