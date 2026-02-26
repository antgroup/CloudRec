package aws_elasticache_redis_world_open_and_internet_reachable_900044
import rego.v1

default risk := false

risk if {
  is_redis_engine
  internet_reachable
  world_open_redis_port
}

messages contains {"Description": "ElastiCache Redis存在公网链路且安全组对公网放通Redis端口/全流量。"} if {
  risk
}

is_redis_engine if {
  lower(input.CacheCluster.Engine) == "redis"
}

internet_reachable if {
  input.NetworkExposure.HasInternetGatewayRoute == true
  input.NetworkExposure.HasPublicSubnet == true
}

world_open_redis_port if {
  some sg in input.SecurityGroups
  some r in sg.SecurityGroupRules
  r.IsEgress != true
  world_cidr(r)
  rule_allows_redis(r)
}

world_cidr(r) if {
  r.CidrIpv4 == "0.0.0.0/0"
}

world_cidr(r) if {
  r.CidrIpv6 == "::/0"
}

rule_allows_redis(r) if {
  r.IpProtocol == "-1"
}

rule_allows_redis(r) if {
  lower(r.IpProtocol) == "tcp"
  r.FromPort != null
  r.ToPort != null
  redis_port := redis_ports[_]
  to_number(r.FromPort) <= redis_port
  to_number(r.ToPort) >= redis_port
}

redis_ports := [6379, 6380]
