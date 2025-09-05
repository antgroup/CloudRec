package ecs_disk_encryption_check_12200006
import rego.v1

default risk := false

risk if {
    some i
    input.Disks[i].Encrypted == false
}

instance_id := input.Instance.InstanceId
