package polardb_enable_audit_log_9500001
import rego.v1

default risk := false
risk if {
    input.DBClusterAuditLogCollector.CollectorStatus == "Disabled"
}