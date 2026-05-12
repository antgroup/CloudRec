package elasticsearch_disk_encryption_check_12200007
import rego.v1

default risk := false

risk if {
    input.InstanceDetail.nodeSpec.diskEncryption == false
}

instanceId := input.InstanceDetail.instanceId