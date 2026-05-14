package maxcompute

import (
	"context"
	"testing"

	"github.com/core-sdk/constant"
)

func TestMaxComputeTenantIDFromContextConfig(t *testing.T) {
	ctx := context.WithValue(context.Background(), constant.CloudAccountConfig, map[string]string{
		"maxcompute_tenant_id": "tenant-1",
	})

	if got := maxComputeTenantID(ctx); got != "tenant-1" {
		t.Fatalf("maxComputeTenantID() = %q, want tenant-1", got)
	}
}

func TestMaxComputeRegionSkipsGlobal(t *testing.T) {
	ctx := context.WithValue(context.Background(), constant.RegionId, "global")
	if got := maxComputeRegion(ctx); got != "" {
		t.Fatalf("maxComputeRegion(global) = %q, want empty", got)
	}

	ctx = context.WithValue(context.Background(), constant.RegionId, "cn-hangzhou")
	if got := maxComputeRegion(ctx); got != "cn-hangzhou" {
		t.Fatalf("maxComputeRegion() = %q, want cn-hangzhou", got)
	}
}
