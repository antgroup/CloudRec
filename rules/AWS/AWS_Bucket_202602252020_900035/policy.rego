package aws_s3_public_access_block_incomplete_900035
import rego.v1

default risk := false

risk if {
  input.PublicAccessBlock == null
}

risk if {
  p := input.PublicAccessBlock.PublicAccessBlockConfiguration
  p.BlockPublicAcls != true
}

risk if {
  p := input.PublicAccessBlock.PublicAccessBlockConfiguration
  p.IgnorePublicAcls != true
}

risk if {
  p := input.PublicAccessBlock.PublicAccessBlockConfiguration
  p.BlockPublicPolicy != true
}

risk if {
  p := input.PublicAccessBlock.PublicAccessBlockConfiguration
  p.RestrictPublicBuckets != true
}

messages contains {"Description": "S3公共访问阻断配置不完整。"} if {
  risk
}
