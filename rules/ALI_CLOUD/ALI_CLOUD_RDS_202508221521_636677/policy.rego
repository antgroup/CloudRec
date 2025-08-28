package rds_ssl_encryption_12200005
import rego.v1

default risk := false

risk if {
    input.DBInstanceSSL.SSLEnabled != "No"
}

DBInstanceID := input.DBInstanceAttribute.DBInstanceId
SSLStatus := input.DBInstanceSSL.SSLEnabled
