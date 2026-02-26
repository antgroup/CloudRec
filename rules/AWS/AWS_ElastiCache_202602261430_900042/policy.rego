package aws_elasticache_redis_no_auth_token_900042
import rego.v1

default risk := false

risk if {
  is_redis_engine
  input.CacheCluster.AuthTokenEnabled != true
}

messages contains {"Description": "ElastiCache Redis未启用认证令牌（AUTH）。"} if {
  risk
}

is_redis_engine if {
  lower(input.CacheCluster.Engine) == "redis"
}
