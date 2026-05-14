package alicloud

import (
	"context"
	"errors"
	"fmt"
	"strings"

	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
)

const ProviderName = "alicloud"

var ErrSDKCollectionNotImplemented = errors.New("alicloud sdk collection is not implemented yet")

// Collector is the future seam for real Alibaba Cloud SDK collection.
type Collector interface {
	Collect(ctx context.Context, account liteprovider.Account, credentials Credentials) ([]liteprovider.Asset, error)
}

type Provider struct {
	collector Collector
	validator AccountValidator
}

type Option func(*Provider)

var _ liteprovider.Provider = (*Provider)(nil)

func New(options ...Option) *Provider {
	provider := &Provider{
		collector: NewDefaultCollector(),
		validator: IMSAccountValidator{},
	}
	for _, option := range options {
		option(provider)
	}
	return provider
}

func WithCollector(collector Collector) Option {
	return func(provider *Provider) {
		if collector != nil {
			provider.collector = collector
		}
	}
}

func WithAccountValidator(validator AccountValidator) Option {
	return func(provider *Provider) {
		if validator != nil {
			provider.validator = validator
		}
	}
}

func (p *Provider) Name() string {
	return ProviderName
}

func (p *Provider) ValidateAccount(ctx context.Context, account liteprovider.Account) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if account.Provider != "" && account.Provider != ProviderName {
		return fmt.Errorf("alicloud provider cannot validate account for provider %q", account.Provider)
	}
	if strings.TrimSpace(account.AccountID) == "" {
		return errors.New("alicloud provider requires account id")
	}

	if fixturePath(account) != "" {
		return nil
	}

	if _, err := ResolveCredentials(account); err != nil {
		return fmt.Errorf("alicloud credentials: %w", err)
	}
	if skipAccountValidation(account) {
		return nil
	}
	if p.validator != nil {
		credentials, err := ResolveCredentials(account)
		if err != nil {
			return fmt.Errorf("alicloud credentials: %w", err)
		}
		if err := p.validator.Validate(ctx, account, credentials); err != nil {
			return fmt.Errorf("alicloud account validation: %w", err)
		}
	}
	return nil
}

func (p *Provider) CollectAssets(ctx context.Context, account liteprovider.Account) ([]liteprovider.Asset, error) {
	if err := p.ValidateAccount(ctx, account); err != nil {
		return nil, err
	}

	if path := fixturePath(account); path != "" {
		return loadFixtureAssets(ctx, account, path)
	}

	credentials, err := ResolveCredentials(account)
	if err != nil {
		return nil, fmt.Errorf("alicloud credentials: %w", err)
	}
	account = accountWithResolvedCloudAccountID(ctx, account, credentials)
	if _, err := collectorTimeout(account.Config, defaultLegacyCollectorTimeout); err != nil {
		return nil, err
	}
	if _, err := collectorConcurrency(account.Config, defaultCollectorConcurrency); err != nil {
		return nil, err
	}
	if err := configureLegacyCollectorLogging(account.Config); err != nil {
		return nil, err
	}
	return p.collector.Collect(ctx, account, credentials)
}

type notImplementedCollector struct{}

func (notImplementedCollector) Collect(context.Context, liteprovider.Account, Credentials) ([]liteprovider.Asset, error) {
	return nil, ErrSDKCollectionNotImplemented
}

func fixturePath(account liteprovider.Account) string {
	return strings.TrimSpace(account.Config["fixture"])
}

func skipAccountValidation(account liteprovider.Account) bool {
	value := strings.ToLower(strings.TrimSpace(account.Config["skip_account_validation"]))
	return value == "1" || value == "true" || value == "yes"
}
