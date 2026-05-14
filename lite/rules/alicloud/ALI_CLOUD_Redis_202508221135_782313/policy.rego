package redis_vpc_check_12200002
import rego.v1
default risk := false


risk if {
    count(instances_without_vpc) + count(instances_with_empty_vpc) > 0
}

# 无VpcId字段或者VpcId为空认为存在风险

instances_without_vpc contains InstanceId if {
    instance := input.DBInstanceAttribute[_]
    InstanceId := instance.InstanceId
    not instance.VpcId
}

instances_with_empty_vpc contains InstanceId if {
    instance := input.DBInstanceAttribute[_]
    InstanceId := instance.InstanceId
    instance.VpcId == ""
}