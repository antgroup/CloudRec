package alicloud

import (
	"context"
	"errors"
	"testing"
	"time"

	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
	coreconstant "github.com/core-sdk/constant"
	coreschema "github.com/core-sdk/schema"
)

func TestDefaultCollectorIncludesP1ResourceAdapters(t *testing.T) {
	collector, ok := NewDefaultCollector().(*HybridCollector)
	if !ok {
		t.Fatalf("NewDefaultCollector returned %T, want *HybridCollector", NewDefaultCollector())
	}

	for _, resourceType := range []string{
		"RAM User",
		"RAM Role",
		"ECS",
		"Security Group",
		"SLB",
		"ALB",
		"NLB",
		"RDS",
		"Redis",
		"MongoDB",
	} {
		if !collector.native.HasAdapter(resourceType) {
			t.Fatalf("default native registry missing %q adapter", resourceType)
		}
	}
}

func TestECSAndSecurityGroupAdaptersCollectAssetsByRegion(t *testing.T) {
	serviceFactory := func(AdapterRequest, coreschema.Resource, string) (coreschema.ServiceInterface, error) {
		return fakeLegacyService{}, nil
	}

	ecsAdapter := NewECSAdapter(
		WithResourceFunctionResource(fakeECSResource(func(ctx context.Context, _ coreschema.ServiceInterface, res chan<- any) error {
			region := ctx.Value(coreconstant.RegionId).(string)
			res <- map[string]any{
				"Instance": map[string]any{
					"InstanceId":   "i-" + region,
					"InstanceName": "ecs-" + region,
					"RegionId":     region,
					"SecurityGroupIds": map[string]any{
						"SecurityGroupId": []string{"sg-" + region},
					},
				},
			}
			return nil
		})),
		WithResourceFunctionServiceFactory(serviceFactory),
	)
	ecsAssets, err := ecsAdapter.Collect(context.Background(), AdapterRequest{
		Account:     liteprovider.Account{AccountID: "123456789"},
		Credentials: Credentials{AccessKeyID: "unit-ak", AccessKeySecret: "unit-sk"},
		Regions:     []string{"cn-hangzhou", "cn-beijing"},
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("ECS Collect returned error: %v", err)
	}
	if len(ecsAssets) != 2 {
		t.Fatalf("len(ecsAssets) = %d, want 2", len(ecsAssets))
	}
	if ecsAssets[0].ID != "alicloud://123456789/cn-hangzhou/ECS/i-cn-hangzhou" {
		t.Fatalf("first ECS asset ID = %q, want cn-hangzhou asset", ecsAssets[0].ID)
	}
	if ecsAssets[1].ID != "alicloud://123456789/cn-beijing/ECS/i-cn-beijing" {
		t.Fatalf("second ECS asset ID = %q, want cn-beijing asset", ecsAssets[1].ID)
	}

	sgAdapter := NewSecurityGroupAdapter(
		WithResourceFunctionResource(fakeSecurityGroupResource(func(ctx context.Context, _ coreschema.ServiceInterface, res chan<- any) error {
			region := ctx.Value(coreconstant.RegionId).(string)
			res <- map[string]any{
				"SecurityGroup": map[string]any{
					"SecurityGroupId":   "sg-" + region,
					"SecurityGroupName": "sg-" + region,
					"RegionId":          region,
				},
			}
			return nil
		})),
		WithResourceFunctionServiceFactory(serviceFactory),
	)
	sgAssets, err := sgAdapter.Collect(context.Background(), AdapterRequest{
		Account:     liteprovider.Account{AccountID: "123456789"},
		Credentials: Credentials{AccessKeyID: "unit-ak", AccessKeySecret: "unit-sk"},
		Regions:     []string{"cn-hangzhou", "cn-beijing"},
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("Security Group Collect returned error: %v", err)
	}
	if len(sgAssets) != 2 {
		t.Fatalf("len(sgAssets) = %d, want 2", len(sgAssets))
	}
	if sgAssets[0].ID != "alicloud://123456789/cn-hangzhou/Security_Group/sg-cn-hangzhou" {
		t.Fatalf("first security group asset ID = %q, want cn-hangzhou asset", sgAssets[0].ID)
	}
	if sgAssets[1].ID != "alicloud://123456789/cn-beijing/Security_Group/sg-cn-beijing" {
		t.Fatalf("second security group asset ID = %q, want cn-beijing asset", sgAssets[1].ID)
	}
}

func TestResourceFunctionAdapterReturnsPartialErrorAndPreservesAssets(t *testing.T) {
	adapter := NewECSAdapter(
		WithResourceFunctionResource(fakeECSResource(func(ctx context.Context, _ coreschema.ServiceInterface, res chan<- any) error {
			region := ctx.Value(coreconstant.RegionId).(string)
			if region == "cn-beijing" {
				return errors.New("regional api failed")
			}
			res <- map[string]any{
				"Instance": map[string]any{
					"InstanceId":   "i-success",
					"InstanceName": "i-success",
					"RegionId":     region,
				},
			}
			return nil
		})),
		WithResourceFunctionServiceFactory(func(AdapterRequest, coreschema.Resource, string) (coreschema.ServiceInterface, error) {
			return fakeLegacyService{}, nil
		}),
	)

	assets, err := adapter.Collect(context.Background(), AdapterRequest{
		Account:     liteprovider.Account{AccountID: "123456789"},
		Credentials: Credentials{AccessKeyID: "unit-ak", AccessKeySecret: "unit-sk"},
		Regions:     []string{"cn-hangzhou", "cn-beijing"},
		Timeout:     time.Second,
	})
	if err == nil {
		t.Fatal("expected partial collection error")
	}
	var partial *liteprovider.PartialCollectionError
	if !errors.As(err, &partial) {
		t.Fatalf("error = %T, want PartialCollectionError", err)
	}
	if len(assets) != 1 || len(partial.Assets) != 1 {
		t.Fatalf("assets = %#v, partial assets = %#v, want preserved successful asset", assets, partial.Assets)
	}
	if partial.Failures[0].Region != "cn-beijing" {
		t.Fatalf("failure region = %q, want cn-beijing", partial.Failures[0].Region)
	}
}

func TestSDKRegionForGlobalCollectionUsesCallableRegion(t *testing.T) {
	got := sdkRegionForCollection(AdapterRequest{
		Account: liteprovider.Account{
			AccountID:     "123456789",
			DefaultRegion: "cn-shanghai",
		},
		Credentials: Credentials{AccessKeyID: "unit-ak", AccessKeySecret: "unit-sk"},
		Regions:     []string{"global"},
	}, "global")
	if got != "cn-shanghai" {
		t.Fatalf("sdk region = %q, want cn-shanghai", got)
	}

	got = sdkRegionForCollection(AdapterRequest{
		Account:     liteprovider.Account{AccountID: "123456789"},
		Credentials: Credentials{AccessKeyID: "unit-ak", AccessKeySecret: "unit-sk", Region: "cn-hangzhou"},
		Regions:     []string{"global"},
	}, "global")
	if got != "cn-hangzhou" {
		t.Fatalf("sdk region = %q, want credential region", got)
	}
}

func TestResourceFunctionTimeoutExtendsDefaultRAMTimeout(t *testing.T) {
	request := AdapterRequest{}
	got := resourceFunctionTimeout(request, "RAM User", 30*time.Second)
	if got != 90*time.Second {
		t.Fatalf("resourceFunctionTimeout() = %s, want 90s", got)
	}

	request.Account.Config = map[string]string{"collector_timeout": "30s"}
	got = resourceFunctionTimeout(request, "RAM User", 30*time.Second)
	if got != 30*time.Second {
		t.Fatalf("explicit timeout was overridden: got %s", got)
	}
}

func TestDatabaseClientsUseSDKEndpointMap(t *testing.T) {
	credentials := Credentials{AccessKeyID: "unit-ak", AccessKeySecret: "unit-sk"}

	rdsClient, err := newRDSClient("cn-hangzhou", newOpenAPIConfig("cn-hangzhou", credentials, time.Second))
	if err != nil {
		t.Fatalf("newRDSClient returned error: %v", err)
	}
	if rdsClient.Endpoint == nil || *rdsClient.Endpoint != "rds.aliyuncs.com" {
		t.Fatalf("RDS endpoint = %v, want SDK mapped endpoint", rdsClient.Endpoint)
	}

	redisClient, err := newRedisClient("cn-hangzhou", newOpenAPIConfig("cn-hangzhou", credentials, time.Second))
	if err != nil {
		t.Fatalf("newRedisClient returned error: %v", err)
	}
	if redisClient.Endpoint == nil || *redisClient.Endpoint != "r-kvstore.aliyuncs.com" {
		t.Fatalf("Redis endpoint = %v, want SDK mapped endpoint", redisClient.Endpoint)
	}

	mongoClient, err := newMongoDBClient("cn-hangzhou", newOpenAPIConfig("cn-hangzhou", credentials, time.Second))
	if err != nil {
		t.Fatalf("newMongoDBClient returned error: %v", err)
	}
	if mongoClient.Endpoint == nil || *mongoClient.Endpoint != "mongodb.aliyuncs.com" {
		t.Fatalf("MongoDB endpoint = %v, want SDK mapped endpoint", mongoClient.Endpoint)
	}
}

func TestECSAdapterFillsSecurityGroupRelationships(t *testing.T) {
	adapter := NewECSAdapter(
		WithResourceFunctionResource(fakeECSResource(func(context.Context, coreschema.ServiceInterface, chan<- any) error {
			return nil
		})),
	)
	asset, err := adapter.assetFromData(liteprovider.Account{AccountID: "123456789"}, "cn-hangzhou", map[string]any{
		"Instance": map[string]any{
			"InstanceId":   "i-1",
			"InstanceName": "i-1",
			"SecurityGroupIds": map[string]any{
				"SecurityGroupId": []string{"sg-1"},
			},
		},
	})
	if err != nil {
		t.Fatalf("assetFromData returned error: %v", err)
	}
	if len(asset.Relationships) != 1 {
		t.Fatalf("relationships = %#v, want one security group relationship", asset.Relationships)
	}
	relationship := asset.Relationships[0]
	if relationship.Type != "uses_security_group" {
		t.Fatalf("relationship type = %q, want uses_security_group", relationship.Type)
	}
	if relationship.TargetID != "alicloud://123456789/cn-hangzhou/Security_Group/sg-1" {
		t.Fatalf("relationship TargetID = %q, want stable security group asset ID", relationship.TargetID)
	}
}

func fakeECSResource(fn func(context.Context, coreschema.ServiceInterface, chan<- any) error) coreschema.Resource {
	return coreschema.Resource{
		ResourceType: "ECS",
		RowField: coreschema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Dimension:          coreschema.Regional,
		ResourceDetailFunc: fn,
	}
}

func fakeSecurityGroupResource(fn func(context.Context, coreschema.ServiceInterface, chan<- any) error) coreschema.Resource {
	return coreschema.Resource{
		ResourceType: "Security Group",
		RowField: coreschema.RowField{
			ResourceId:   "$.SecurityGroup.SecurityGroupId",
			ResourceName: "$.SecurityGroup.SecurityGroupName",
		},
		Dimension:          coreschema.Regional,
		ResourceDetailFunc: fn,
	}
}
