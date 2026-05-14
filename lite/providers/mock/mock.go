package mock

import (
	"context"
	"fmt"

	"github.com/antgroup/CloudRec/lite/internal/provider"
)

const ProviderName = "mock"

// Provider returns deterministic demo assets for local development and tests.
type Provider struct{}

var _ provider.Provider = (*Provider)(nil)

func New() *Provider {
	return &Provider{}
}

func (p *Provider) Name() string {
	return ProviderName
}

func (p *Provider) ValidateAccount(ctx context.Context, account provider.Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if account.Provider != "" && account.Provider != ProviderName {
		return fmt.Errorf("mock provider cannot validate account for provider %q", account.Provider)
	}
	if account.AccountID == "" {
		return fmt.Errorf("mock provider requires account id")
	}

	return nil
}

func (p *Provider) CollectAssets(ctx context.Context, account provider.Account) ([]provider.Asset, error) {
	if err := p.ValidateAccount(ctx, account); err != nil {
		return nil, err
	}

	accountID := account.AccountID
	region := account.DefaultRegion
	if region == "" {
		region = "mock-region-1"
	}

	networkID := fmt.Sprintf("mock://%s/%s/network/vpc-main", accountID, region)

	return []provider.Asset{
		{
			ID:        networkID,
			Provider:  ProviderName,
			AccountID: accountID,
			Type:      "network.vpc",
			Name:      "vpc-main",
			Region:    region,
			Tags: map[string]string{
				"env":   "dev",
				"owner": "cloudrec-lite",
			},
			Properties: map[string]any{
				"cidr":              "10.0.0.0/16",
				"internet_exposed":  true,
				"default_network":   true,
				"provider_resource": "mock_vpc",
			},
		},
		{
			ID:        fmt.Sprintf("mock://%s/%s/compute/instance-web-01", accountID, region),
			Provider:  ProviderName,
			AccountID: accountID,
			Type:      "compute.instance",
			Name:      "instance-web-01",
			Region:    region,
			Tags: map[string]string{
				"env":  "dev",
				"role": "web",
			},
			Properties: map[string]any{
				"public_ip":         "203.0.113.10",
				"state":             "running",
				"open_ports":        []int{22, 443},
				"provider_resource": "mock_instance",
			},
			Relationships: []provider.Relationship{
				{
					Type:     "member_of",
					TargetID: networkID,
				},
			},
		},
		{
			ID:        fmt.Sprintf("mock://%s/global/storage/bucket-public-assets", accountID),
			Provider:  ProviderName,
			AccountID: accountID,
			Type:      "storage.bucket",
			Name:      "bucket-public-assets",
			Region:    "global",
			Tags: map[string]string{
				"env":  "dev",
				"data": "sample",
			},
			Properties: map[string]any{
				"public":            true,
				"encryption":        "disabled",
				"versioning":        false,
				"provider_resource": "mock_bucket",
			},
		},
	}, nil
}

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{
		AssetTypes: []string{
			"compute.instance",
			"network.vpc",
			"storage.bucket",
		},
		Regions: []string{
			"global",
			"mock-region-1",
		},
		SupportsAccountValidation:     true,
		SupportsIncrementalCollection: false,
		SupportsResourceRelationships: true,
		MaxConcurrency:                1,
	}
}
