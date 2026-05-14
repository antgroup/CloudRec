package collector

import (
	"testing"

	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
)

func TestInitServicesCreatesVPCClientForVPNGateway(t *testing.T) {
	services := &Services{}
	err := services.InitServices(schema.CloudAccountParam{
		CloudAccountId: "123456789",
		Platform:       string(constant.AlibabaCloud),
		ResourceType:   VPNGateway,
		CommonCloudAccountParam: schema.CommonCloudAccountAuthParam{
			AK:     "test-ak",
			SK:     "test-sk",
			Region: "cn-hangzhou",
		},
	})
	if err != nil {
		t.Fatalf("InitServices() error = %v", err)
	}
	if services.VPC == nil {
		t.Fatal("InitServices() left VPC nil for VPN Gateway")
	}
}
