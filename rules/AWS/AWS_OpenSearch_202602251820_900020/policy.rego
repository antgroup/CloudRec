package aws_opensearch_vpc_sg_443_exposed_900020
import rego.v1

default risk := false

risk if {
  in_vpc
  some sgd in input.SecurityGroups
  some perm in sgd.SecurityGroup.IpPermissions
  some r in perm.IpRanges
  r.CidrIp == "0.0.0.0/0"
  exposes_443(perm)
}

messages contains {"Description": "OpenSearch关联安全组对公网开放443端口。"} if {
  risk
}

in_vpc if {
  input.DomainStatus.VPCOptions != null
  count(input.DomainStatus.VPCOptions.SecurityGroupIds) > 0
}

exposes_443(perm) if {
  perm.IpProtocol == "-1"
}

exposes_443(perm) if {
  perm.FromPort != null
  perm.ToPort != null
  to_number(perm.FromPort) <= 443
  to_number(perm.ToPort) >= 443
}
