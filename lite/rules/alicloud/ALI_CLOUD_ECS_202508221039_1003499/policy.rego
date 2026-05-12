package ecs_instance_vpc_check_12200001
import rego.v1
default risk := false

risk if {
    input.Instance.Status == "Running"
    not input.Instance.VpcAttributes.VpcId
}
risk if {
    input.Instance.Status == "Running"
    input.Instance.VpcAttributes.VpcId == ""
}

VpcId := input.Instance.VpcAttributes.VpcId