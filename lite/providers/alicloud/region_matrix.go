package alicloud

import "strings"

// The resource-region matrix is intentionally an exceptions-only table.
// Resource types that are not listed here keep the collector catalog's region
// list unchanged, so newly added Alibaba Cloud regions are scanned by default.
// Operators can also bypass every matrix rule with explicit --region/--regions.
type regionMatrixMode string

const (
	regionMatrixSingleEndpoint regionMatrixMode = "single_endpoint"
	regionMatrixExcludeRegions regionMatrixMode = "exclude_regions"
	regionMatrixSupportedOnly  regionMatrixMode = "supported_only"
)

type regionMatrixRule struct {
	ResourceType         string
	Mode                 regionMatrixMode
	EndpointRegion       string
	SupportedRegions     []string
	ExcludedRegions      []string
	Reason               string
	ReviewSource         string
	LastReviewed         string
	ExplicitRegionPolicy string
}

func alicloudRegionMatrixRules() []regionMatrixRule {
	return []regionMatrixRule{
		{
			ResourceType:         "CERT",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"ap-southeast-5"},
			Reason:               "CAS endpoint DNS failed in ap-southeast-5.",
			ReviewSource:         "2026-05-06 scan_task_runs analysis",
			LastReviewed:         "2026-05-06",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "CDN",
			Mode:                 regionMatrixSingleEndpoint,
			EndpointRegion:       "cn-hangzhou",
			Reason:               "CDN domain APIs are account-level. Scanning every regional endpoint duplicates work and produced noisy deleted-domain calls.",
			ReviewSource:         "debug log 2026-05-04 plus collector/cdn implementation review",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "ClickHouse",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"ap-southeast-3"},
			Reason:               "ClickHouse endpoint DNS failed in ap-southeast-3.",
			ReviewSource:         "2026-05-06 scan_task_runs analysis",
			LastReviewed:         "2026-05-06",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "DCDN Domain",
			Mode:                 regionMatrixSingleEndpoint,
			EndpointRegion:       "cn-hangzhou",
			Reason:               "DescribeDcdnUserDomains is an account-level domain list; the same four domains appeared in 21 regional scans.",
			ReviewSource:         "2026-05-06 scan_task_runs / asset table analysis",
			LastReviewed:         "2026-05-06",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "DMS",
			Mode:                 regionMatrixSingleEndpoint,
			EndpointRegion:       "cn-hangzhou",
			Reason:               "ListUserTenants is a tenant-level DMS API without a request Region parameter; scanning all endpoints produced the same tenant under 18 regional task records.",
			ReviewSource:         "2026-05-06 scan_task_runs / asset table analysis plus DMS ListUserTenants/ListInstances API review",
			LastReviewed:         "2026-05-06",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "DNS",
			Mode:                 regionMatrixSingleEndpoint,
			EndpointRegion:       "cn-hangzhou",
			Reason:               "Alidns results are account-level product instances; 19 regional scans emitted the same DNS product instance.",
			ReviewSource:         "2026-05-06 scan_task_runs / asset table analysis",
			LastReviewed:         "2026-05-06",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "VOD Domain",
			Mode:                 regionMatrixSingleEndpoint,
			EndpointRegion:       "cn-shanghai",
			Reason:               "VOD domain API returns InvalidOperation.NotSupportedEndpoint outside cn-shanghai and explicitly asks for cn-shanghai.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "MSE Cluster",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-zhengzhou-jva"},
			Reason:               "Known unsupported profile region in current MSE endpoint set; future upstream regions still flow through by default.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "ECS Image",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-hangzhou-finance"},
			Reason:               "ECS image endpoint rejected this finance region with NotSupportedEndpoint.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "ECS Snapshot",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-hangzhou-finance"},
			Reason:               "ECS snapshot endpoint rejected this finance region with NotSupportedEndpoint.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "ECI ContainerGroup",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"me-central-1", "cn-hangzhou-finance", "cn-beijing-finance-1", "cn-shanghai-finance-1", "cn-shenzhen-finance-1"},
			Reason:               "ECI returned invalid region / endpoint resolution errors for these regions.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "ECI ImageCache",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"me-central-1", "cn-hangzhou-finance", "cn-beijing-finance-1", "cn-shanghai-finance-1", "cn-shenzhen-finance-1"},
			Reason:               "ECI returned invalid region / endpoint resolution errors for these regions.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "Elasticsearch",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-hangzhou-finance", "cn-shanghai-finance-1"},
			Reason:               "Elasticsearch reported the service is not activated in these finance regions.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "KMS",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-fuzhou", "cn-wuhan-lr", "cn-zhengzhou-jva", "na-south-1", "cn-hangzhou-finance"},
			Reason:               "KMS returned UnsupportedOperation / This action is not supported in these observed regions.",
			ReviewSource:         "2026-05-06 scan_task_runs analysis",
			LastReviewed:         "2026-05-06",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "Logstash",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-hangzhou-finance", "cn-shanghai-finance-1"},
			Reason:               "Logstash reported the service is not activated in these finance regions.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "API Gateway",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-nanjing", "cn-fuzhou"},
			Reason:               "Legacy CloudAPI endpoint did not resolve in these observed regions.",
			ReviewSource:         "debug log 2026-05-04 and 2026-05-05 scan analysis",
			LastReviewed:         "2026-05-05",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "APIG",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-heyuan", "cn-guangzhou", "ap-southeast-6", "ap-southeast-7", "eu-west-1", "me-east-1", "me-central-1"},
			Reason:               "APIG 2024 endpoint did not resolve in these observed regions.",
			ReviewSource:         "debug log 2026-05-04 and 2026-05-05 scan analysis",
			LastReviewed:         "2026-05-05",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "Message Service Queue",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-nanjing", "cn-fuzhou"},
			Reason:               "MNS open endpoint DNS failed in these observed regions.",
			ReviewSource:         "2026-05-06 scan_task_runs analysis",
			LastReviewed:         "2026-05-06",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "CEN",
			Mode:                 regionMatrixSingleEndpoint,
			EndpointRegion:       "cn-hangzhou",
			Reason:               "CEN DescribeCens is account-level in the legacy collector; running the same detail flow in every region duplicates work and repeatedly triggers CenId/RegionId validation warnings.",
			ReviewSource:         "debug log 2026-05-05 scan analysis plus collector/cen implementation review",
			LastReviewed:         "2026-05-05",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "ECP Instance",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-hangzhou", "cn-beijing", "cn-shenzhen", "cn-qingdao", "cn-zhangjiakou", "cn-huhehaote", "cn-wulanchabu", "cn-chengdu", "cn-hongkong", "ap-southeast-1", "ap-southeast-3", "ap-southeast-5", "ap-northeast-1", "eu-central-1", "us-east-1", "us-west-1"},
			Reason:               "ECP eds-aic endpoint DNS failed in the observed regions; ap-southeast-1 returned ProfileRegion.Unsupported.",
			ReviewSource:         "debug log 2026-05-05 scan analysis and 2026-05-06 scan_task_runs analysis",
			LastReviewed:         "2026-05-06",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "Eflo Cluster",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-qingdao", "cn-nanjing", "cn-chengdu", "ap-southeast-5", "us-east-1", "us-west-1", "eu-west-1", "ap-northeast-2", "ap-southeast-6", "me-central-1", "cn-fuzhou", "cn-beijing-finance-1", "cn-hangzhou-finance", "cn-shanghai-finance-1", "cn-shenzhen-finance-1"},
			Reason:               "Eflo controller endpoint DNS failed in these observed regions; transient 503 regions are not excluded here.",
			ReviewSource:         "debug log 2026-05-05 scan analysis",
			LastReviewed:         "2026-05-05",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "Hologram Instance",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-qingdao", "cn-huhehaote", "cn-nanjing", "cn-heyuan", "cn-guangzhou", "eu-west-1", "ap-southeast-6", "ap-southeast-7", "me-central-1", "cn-fuzhou", "cn-beijing-finance-1"},
			Reason:               "Hologram endpoint DNS failed in these observed regions.",
			ReviewSource:         "debug log 2026-05-05 scan analysis",
			LastReviewed:         "2026-05-05",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "SelectDB",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-shanghai", "cn-heyuan", "ap-northeast-2", "ap-southeast-3", "ap-southeast-7"},
			Reason:               "SelectDB endpoint DNS failed in these observed regions.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "SWAS",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"me-east-1", "cn-beijing-finance-1", "cn-hangzhou-finance", "cn-shanghai-finance-1", "cn-shenzhen-finance-1"},
			Reason:               "SWAS endpoint DNS failed in these observed regions.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "ONS Instance",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-fuzhou", "cn-wulanchabu", "cn-nanjing", "cn-heyuan", "cn-guangzhou", "ap-northeast-2", "ap-southeast-7"},
			Reason:               "ONS endpoint DNS failed in these observed regions.",
			ReviewSource:         "debug log 2026-05-04 and 2026-05-05 scan analysis",
			LastReviewed:         "2026-05-05",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "TraceApp",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-nanjing"},
			Reason:               "ARMS TraceApp endpoint DNS failed in cn-nanjing; 503-only regions are kept for future scans.",
			ReviewSource:         "debug log 2026-05-05 scan analysis",
			LastReviewed:         "2026-05-05",
			ExplicitRegionPolicy: "honor",
		},
		{
			ResourceType:         "RocketMQ",
			Mode:                 regionMatrixExcludeRegions,
			ExcludedRegions:      []string{"cn-nanjing"},
			Reason:               "RocketMQ endpoint DNS failed in cn-nanjing.",
			ReviewSource:         "debug log 2026-05-04",
			LastReviewed:         "2026-05-04",
			ExplicitRegionPolicy: "honor",
		},
	}
}

func applyRegionMatrix(resourceType string, candidateRegions []string, explicit bool) []string {
	regions := uniqueRegions(candidateRegions)
	if explicit {
		return regions
	}
	rule, ok := regionMatrixRuleFor(resourceType)
	if !ok {
		return regions
	}
	switch rule.Mode {
	case regionMatrixSingleEndpoint:
		if strings.TrimSpace(rule.EndpointRegion) == "" {
			return regions
		}
		return []string{strings.TrimSpace(rule.EndpointRegion)}
	case regionMatrixSupportedOnly:
		return intersectRegions(regions, rule.SupportedRegions)
	case regionMatrixExcludeRegions:
		return excludeRegions(regions, rule.ExcludedRegions)
	default:
		return regions
	}
}

func regionMatrixRuleFor(resourceType string) (regionMatrixRule, bool) {
	normalized := normalizeResourceType(resourceType)
	for _, rule := range alicloudRegionMatrixRules() {
		if normalizeResourceType(rule.ResourceType) == normalized {
			return rule, true
		}
	}
	return regionMatrixRule{}, false
}

func uniqueRegions(regions []string) []string {
	seen := map[string]bool{}
	values := make([]string, 0, len(regions))
	for _, region := range regions {
		region = strings.TrimSpace(region)
		if region == "" || seen[region] {
			continue
		}
		seen[region] = true
		values = append(values, region)
	}
	return values
}

func intersectRegions(regions []string, allowlist []string) []string {
	allowed := map[string]bool{}
	for _, region := range allowlist {
		region = strings.TrimSpace(region)
		if region != "" {
			allowed[region] = true
		}
	}
	values := make([]string, 0, len(regions))
	for _, region := range regions {
		if allowed[region] {
			values = append(values, region)
		}
	}
	return values
}
