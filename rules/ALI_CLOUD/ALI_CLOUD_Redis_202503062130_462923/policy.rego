package enable_audit_log_6800006
import rego.v1

default risk := false
risk if {
    input.AuditLogConfig.DbAudit == "false"
}