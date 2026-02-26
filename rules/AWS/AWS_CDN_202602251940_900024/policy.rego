package aws_cloudfront_allow_http_viewer_900024
import rego.v1

default risk := false

risk if {
  lower(input.Distribution.DefaultCacheBehavior.ViewerProtocolPolicy) == "allow-all"
}

messages contains {"Description": "CloudFront默认缓存行为允许HTTP明文访问。"} if {
  risk
}
