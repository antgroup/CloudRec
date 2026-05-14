package mock

import (
	"context"
	"testing"

	"github.com/antgroup/CloudRec/lite/internal/provider"
)

func TestMockProviderCollectAssets(t *testing.T) {
	p := New()
	account := provider.Account{
		Provider:      ProviderName,
		AccountID:     "demo-account",
		DefaultRegion: "mock-region-1",
	}

	assets, err := p.CollectAssets(context.Background(), account)
	if err != nil {
		t.Fatalf("CollectAssets returned error: %v", err)
	}

	if got, want := len(assets), 3; got != want {
		t.Fatalf("CollectAssets returned %d assets, want %d", got, want)
	}

	seenTypes := map[string]bool{}
	for _, asset := range assets {
		if asset.ID == "" {
			t.Fatalf("asset has empty ID: %#v", asset)
		}
		if asset.Provider != ProviderName {
			t.Fatalf("asset provider = %q, want %q", asset.Provider, ProviderName)
		}
		if asset.AccountID != account.AccountID {
			t.Fatalf("asset account id = %q, want %q", asset.AccountID, account.AccountID)
		}
		if asset.Type == "" {
			t.Fatalf("asset has empty type: %#v", asset)
		}
		if asset.Name == "" {
			t.Fatalf("asset has empty name: %#v", asset)
		}
		seenTypes[asset.Type] = true
	}

	for _, want := range []string{"compute.instance", "network.vpc", "storage.bucket"} {
		if !seenTypes[want] {
			t.Fatalf("missing asset type %q in %#v", want, seenTypes)
		}
	}
}

func TestMockProviderCapabilities(t *testing.T) {
	p := New()
	caps := p.Capabilities()

	if p.Name() != ProviderName {
		t.Fatalf("Name() = %q, want %q", p.Name(), ProviderName)
	}
	if !caps.SupportsAccountValidation {
		t.Fatal("SupportsAccountValidation = false, want true")
	}
	if !caps.SupportsResourceRelationships {
		t.Fatal("SupportsResourceRelationships = false, want true")
	}
	if len(caps.AssetTypes) == 0 {
		t.Fatal("Capabilities returned no asset types")
	}
}

func TestMockProviderValidateAccount(t *testing.T) {
	p := New()

	if err := p.ValidateAccount(context.Background(), provider.Account{Provider: ProviderName}); err == nil {
		t.Fatal("ValidateAccount accepted empty account id")
	}
	if err := p.ValidateAccount(context.Background(), provider.Account{Provider: "aws", AccountID: "demo"}); err == nil {
		t.Fatal("ValidateAccount accepted wrong provider")
	}
	if err := p.ValidateAccount(context.Background(), provider.Account{Provider: ProviderName, AccountID: "demo"}); err != nil {
		t.Fatalf("ValidateAccount rejected valid account: %v", err)
	}
}
