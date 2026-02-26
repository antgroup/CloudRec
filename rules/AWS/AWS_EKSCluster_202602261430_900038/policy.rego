package aws_eks_public_endpoint_open_900038
import rego.v1

default risk := false

risk if {
  input.Cluster.ResourcesVpcConfig.EndpointPublicAccess == true
  cidr_world(input.Cluster.ResourcesVpcConfig.PublicAccessCidrs)
}

messages contains {"Description": "EKS API Server公网开放且允许0.0.0.0/0访问。"} if {
  risk
}

cidr_world(cidrs) if {
  some c in cidrs
  c == "0.0.0.0/0"
}

cidr_world(cidrs) if {
  some c in cidrs
  c == "::/0"
}
