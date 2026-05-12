package cloudapi

import (
	"context"
	"testing"

	"github.com/core-sdk/constant"
)

func TestAppOwnerFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), constant.CloudAccountId, "123456789")
	got := appOwnerFromContext(ctx)
	if got == nil || *got != 123456789 {
		t.Fatalf("appOwnerFromContext() = %#v, want 123456789", got)
	}

	configCtx := context.WithValue(context.Background(), constant.CloudAccountConfig, map[string]string{
		"cloud_account_id": "987654321",
	})
	got = appOwnerFromContext(context.WithValue(configCtx, constant.CloudAccountId, "profile-name"))
	if got == nil || *got != 987654321 {
		t.Fatalf("appOwnerFromContext(config) = %#v, want 987654321", got)
	}

	if got := appOwnerFromContext(context.Background()); got != nil {
		t.Fatalf("appOwnerFromContext(empty) = %#v, want nil", got)
	}

	invalidCtx := context.WithValue(context.Background(), constant.CloudAccountId, "not-a-number")
	if got := appOwnerFromContext(invalidCtx); got != nil {
		t.Fatalf("appOwnerFromContext(invalid) = %#v, want nil", got)
	}
}
