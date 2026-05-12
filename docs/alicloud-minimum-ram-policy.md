# Alibaba Cloud Minimum RAM Policy Draft

This policy is a read-only starting point for CloudRec Lite P1/P2 Alibaba Cloud
coverage. It avoids write actions and covers the current native/resource-function
adapter set: Account, OSS, RAM User, RAM Role, ECS, Security Group, SLB, ALB,
NLB, RDS, Redis, and MongoDB.

For the full 100-resource legacy bridge catalog, prefer Alibaba Cloud's managed
read-only policy first, then tighten by using the coverage report and collection
failure categories.

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ims:GetAccountSummary",
        "ims:GetAccountSecurityPracticeReport",
        "ims:GetPasswordPolicy",
        "ims:GetUserSsoSettings",
        "ims:GetSecurityPreference",
        "ims:GetUser",
        "ims:GetLoginProfile",
        "ram:ListUsers",
        "ram:GetUser",
        "ram:ListGroupsForUser",
        "ram:ListPoliciesForUser",
        "ram:ListAccessKeys",
        "ram:GetAccessKeyLastUsed",
        "ram:ListRoles",
        "ram:GetRole",
        "ram:ListPoliciesForRole",
        "ram:GetPolicy",
        "oss:ListBuckets",
        "oss:GetBucket*",
        "ecs:DescribeInstances",
        "ecs:DescribeDisks",
        "ecs:DescribeNetworkInterfaces",
        "ecs:DescribeInstanceRamRole",
        "ecs:DescribeSecurityGroups",
        "ecs:DescribeSecurityGroupAttribute",
        "slb:Describe*",
        "alb:List*",
        "alb:Get*",
        "nlb:List*",
        "nlb:Get*",
        "rds:Describe*",
        "kvstore:Describe*",
        "dds:Describe*",
        "das:Describe*",
        "vpc:DescribeEipAddresses"
      ],
      "Resource": "*"
    }
  ]
}
```

Validation flow:

```sh
cd lite
go run ./cmd/cloudrec-lite rules coverage --rules ./rules/alicloud --provider alicloud --samples ./samples/alicloud --review-ledger ./rules/alicloud/review-ledger.json --format table
go run ./cmd/cloudrec-lite scan --provider alicloud --account "$ALICLOUD_ACCOUNT_ID" --regions cn-hangzhou --resource-types "Account,OSS,RAM User,RAM Role,ECS,Security Group,SLB,ALB,NLB,RDS,Redis,MongoDB" --rules ./rules/alicloud --dry-run=true --output json --collector-timeout 180s
```

If the scan reports collection failures, use `category` to tune the policy:

- `permission`: add the missing read/list/describe action for that product.
- `product_not_enabled`: keep the policy unchanged; the account has no active service.
- `throttling`: rerun with fewer `--resource-types` or a longer timeout.
- `timeout`: increase `--collector-timeout` for high-cardinality resources such as RAM users.
- `unsupported`: the resource is in the catalog but not yet covered by a native/resource-function adapter.
