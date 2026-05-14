package alicloud

import (
	"context"
	"testing"

	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
)

func TestAccountWithResolvedCloudAccountIDUsesNumericAccountID(t *testing.T) {
	account := accountWithResolvedCloudAccountID(context.Background(), liteprovider.Account{
		AccountID: "1234567890123456",
		Config:    map[string]string{"collector_timeout": "30s"},
	}, Credentials{})

	if got := account.Config[cloudAccountIDConfigKey]; got != "1234567890123456" {
		t.Fatalf("cloud account id = %q, want numeric account id", got)
	}
	if got := account.Config["collector_timeout"]; got != "30s" {
		t.Fatalf("existing config was not preserved: %q", got)
	}
}

func TestAccountWithResolvedCloudAccountIDKeepsConfiguredCloudAccountID(t *testing.T) {
	account := accountWithResolvedCloudAccountID(context.Background(), liteprovider.Account{
		AccountID: "profile-name",
		Config:    map[string]string{cloudAccountIDConfigKey: "1234567890123456"},
	}, Credentials{})

	if got := account.Config[cloudAccountIDConfigKey]; got != "1234567890123456" {
		t.Fatalf("cloud account id = %q, want configured value", got)
	}
}
