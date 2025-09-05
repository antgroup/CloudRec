package mongodb_vpc_check_12200003
import rego.v1
default risk := false

risk if {
    input.DBInstanceAttribute.DBInstanceStatus == "Running"
    not input.DBInstanceAttribute.VPCId
}
risk if {
    input.DBInstanceAttribute.DBInstanceStatus == "Running"
    input.DBInstanceAttribute.VPCId == ""
}

VpcId := input.DBInstanceAttribute.VPCId