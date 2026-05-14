# 阿里云 Resource -> Region 矩阵

本文档说明 CloudRec Lite 如何决定每个阿里云资源类型默认扫描哪些 Region。对应实现位于 `lite/providers/alicloud/region_matrix.go`。

## 设计原则

这个矩阵是“例外表”，不是完整 allowlist。

- 未出现在矩阵里的资源类型，默认保留上游 collector catalog 里的 Region 列表。
- 阿里云新增 Region 后，只要上游资源定义补进了 Region，Lite 默认会继续扫描，不需要同步改矩阵。
- 用户显式传入的 `--region` / `--regions` 永远优先，不会被矩阵过滤。
- 只有 debug 日志或 SDK/官方文档能证明某个产品在某个 Region 无法正确扫描时，才允许新增矩阵规则。
- 优先使用 `exclude_regions`。`supported_only` 容易因为 allowlist 过期而漏掉新 Region，除非 API 官方文档明确说明是封闭支持列表，否则不要使用。

这条约束是 P1 的关键防漏扫机制：矩阵不能演变成一张需要人工追新 Region 的静态大表；新增的收敛规则也只能记录已经证实的例外。

## 当前规则

| Resource type | Mode | Endpoint / 排除 Region | 原因 | 最近确认 |
| --- | --- | --- | --- | --- |
| CERT | `exclude_regions` | `ap-southeast-5` | CAS endpoint DNS 在该 Region 失败。 | 2026-05-06 |
| CDN | `single_endpoint` | endpoint `cn-hangzhou` | CDN 域名 API 是账号级接口；逐 Region 调用会重复扫描，并触发错误的已删除域名请求。 | 2026-05-04 |
| ClickHouse | `exclude_regions` | `ap-southeast-3` | ClickHouse endpoint DNS 在该 Region 失败。 | 2026-05-06 |
| DCDN Domain | `single_endpoint` | endpoint `cn-hangzhou` | `DescribeDcdnUserDomains` 是账号级域名列表；本轮 4 个域名在 21 个 Region 重复出现。 | 2026-05-06 |
| DMS | `single_endpoint` | endpoint `cn-hangzhou` | `ListUserTenants` 是租户级 DMS 接口，请求参数没有 Region；本轮同一租户在 18 个 Region 重复产出。 | 2026-05-06 |
| DNS | `single_endpoint` | endpoint `cn-hangzhou` | Alidns 采集结果在本轮 `scan_task_runs` / 资产表中显示 19 个 Region 产出同一账号级 DNS 产品实例。 | 2026-05-06 |
| VOD Domain | `single_endpoint` | endpoint `cn-shanghai` | VOD 域名 API 在观测到的其他 endpoint 返回不支持，并提示使用 `cn-shanghai`。 | 2026-05-04 |
| MSE Cluster | `exclude_regions` | `cn-zhengzhou-jva` | 当前 MSE endpoint 集合拒绝该 profile region。 | 2026-05-04 |
| ECS Image | `exclude_regions` | `cn-hangzhou-finance` | ECS Image endpoint 在该金融 Region 返回不支持。 | 2026-05-04 |
| ECS Snapshot | `exclude_regions` | `cn-hangzhou-finance` | ECS Snapshot endpoint 在该金融 Region 返回不支持。 | 2026-05-04 |
| ECI ContainerGroup | `exclude_regions` | `me-central-1`、金融 Region | ECI 在这些 Region 返回 invalid region 或 endpoint 解析失败。 | 2026-05-04 |
| ECI ImageCache | `exclude_regions` | `me-central-1`、金融 Region | ECI 在这些 Region 返回 invalid region 或 endpoint 解析失败。 | 2026-05-04 |
| Elasticsearch | `exclude_regions` | `cn-hangzhou-finance`、`cn-shanghai-finance-1` | 服务在这些金融 Region 返回未开通/未激活。 | 2026-05-04 |
| KMS | `exclude_regions` | `cn-fuzhou`、`cn-wuhan-lr`、`cn-zhengzhou-jva`、`na-south-1`、`cn-hangzhou-finance` | KMS 在这些观测 Region 返回 `UnsupportedOperation` / `This action is not supported`。 | 2026-05-06 |
| Logstash | `exclude_regions` | `cn-hangzhou-finance`、`cn-shanghai-finance-1` | 服务在这些金融 Region 返回未开通/未激活。 | 2026-05-04 |
| Message Service Queue | `exclude_regions` | `cn-nanjing`、`cn-fuzhou` | `mns-open` endpoint DNS 在这些观测 Region 失败。 | 2026-05-06 |
| API Gateway | `exclude_regions` | `cn-nanjing`、`cn-fuzhou` | Legacy CloudAPI endpoint 在这些观测 Region 无法解析。 | 2026-05-05 |
| APIG | `exclude_regions` | `cn-heyuan`、`cn-guangzhou`、`ap-southeast-6`、`ap-southeast-7`、`eu-west-1`、`me-east-1`、`me-central-1` | APIG 2024 endpoint 在这些观测 Region 无法解析。 | 2026-05-05 |
| CEN | `single_endpoint` | endpoint `cn-hangzhou` | Legacy collector 的 `DescribeCens` 是账号级入口；逐 Region 调用重复，并触发 `CenId/RegionId` 校验噪音。 | 2026-05-05 |
| ECP Instance | `exclude_regions` | 见代码中的观测 DNS 失败列表，另含 `ap-southeast-1` | `eds-aic` endpoint 在这些观测 Region 无法解析；`ap-southeast-1` 返回 `ProfileRegion.Unsupported`。 | 2026-05-06 |
| Eflo Cluster | `exclude_regions` | 见代码中的观测 DNS 失败列表 | Eflo controller endpoint 在这些观测 Region 无法解析；仅 503 的 Region 不加入矩阵。 | 2026-05-05 |
| Hologram Instance | `exclude_regions` | 见代码中的观测 DNS 失败列表 | Hologram endpoint 在这些观测 Region 无法解析。 | 2026-05-05 |
| SelectDB | `exclude_regions` | `cn-shanghai`、`cn-heyuan`、`ap-northeast-2`、`ap-southeast-3`、`ap-southeast-7` | SelectDB endpoint DNS 在这些观测 Region 失败。 | 2026-05-04 |
| SWAS | `exclude_regions` | `me-east-1`、金融 Region | SWAS endpoint DNS 在这些观测 Region 失败。 | 2026-05-04 |
| ONS Instance | `exclude_regions` | `cn-fuzhou`、`cn-wulanchabu`、`cn-nanjing`、`cn-heyuan`、`cn-guangzhou`、`ap-northeast-2`、`ap-southeast-7` | ONS endpoint DNS 在这些观测 Region 失败。 | 2026-05-05 |
| RocketMQ | `exclude_regions` | `cn-nanjing` | RocketMQ endpoint DNS 在该 Region 失败。 | 2026-05-04 |
| TraceApp | `exclude_regions` | `cn-nanjing` | ARMS TraceApp endpoint DNS 在该 Region 失败；仅 503 的 Region 不加入矩阵。 | 2026-05-05 |

表里的“金融 Region”以代码中的具体列表为准，通常包括 `cn-beijing-finance-1`、`cn-hangzhou-finance`、`cn-shanghai-finance-1`、`cn-shenzhen-finance-1` 中的部分或全部。

## 维护流程

阿里云新增 Region 时：

1. 先更新上游 collector 资源定义的 `Regions` 列表或 SDK endpoint 来源。
2. 不要因为“新增 Region”本身修改本矩阵；矩阵只记录例外。
3. 使用新 Region 做聚焦扫描：

```sh
cloudrec-lite scan --provider alicloud --account "$ALICLOUD_ACCOUNT_ID" --regions <new-region> --resource-types "<resource-type>" --collector-log-level debug --collector-timeout 180s --dry-run=true
```

4. 如果产品扫描正常，矩阵保持不变。
5. 如果产品返回 unsupported-region 或 endpoint-resolution 错误，只把该 Region 加入对应资源的 `exclude_regions`，并更新本文档的原因和确认日期。
6. 如果产品本质是账号级 API，只应走一个固定 endpoint，则新增 `single_endpoint` 规则，并说明为什么逐 Region 扫描会重复或错误。
7. 同步补充 `lite/providers/alicloud/provider_test.go`，确认未知新 Region 仍会被保留。

## 显式覆盖

显式 Region 参数总是优先：

```sh
cloudrec-lite scan --provider alicloud --account "$ALICLOUD_ACCOUNT_ID" --regions cn-new-region-1 --resource-types CDN --collector-log-level debug
```

这用于在默认 catalog 或矩阵变更前，手动验证某个新 Region 的采集行为。
