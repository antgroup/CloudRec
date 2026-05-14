package mongodb_enable_audit_log_9500002
import rego.v1

default risk := false
risk if {
    input.LogAuditStatus == "Disabled"
}