package alicloud

import liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"

func (p *Provider) Capabilities() liteprovider.Capabilities {
	return liteprovider.Capabilities{
		AssetTypes: AllResourceTypes(),
		Regions: []string{
			"global",
			"cn-beijing",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
		},
		SupportsAccountValidation:     true,
		SupportsIncrementalCollection: false,
		SupportsResourceRelationships: true,
		MaxConcurrency:                4,
	}
}
