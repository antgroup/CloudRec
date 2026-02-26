package aws_elasticache_redis_no_transit_encryption_900041
import rego.v1

default risk := false

risk if {
  is_redis_engine
  input.CacheCluster.TransitEncryptionEnabled != true
}

messages contains {"Description": "ElastiCache Redis未开启传输加密。"} if {
  risk
}

is_redis_engine if {
  lower(input.CacheCluster.Engine) == "redis"
}
