package apig

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"github.com/cloudrec/alicloud/collector"
	"os"
	"testing"
)

var GetTestAccount = func() (res []schema.CloudAccount) {
	testAccount := schema.CloudAccount{
		CloudAccountId: "test-account",
		CommonCloudAccountAuthParam: schema.CommonCloudAccountAuthParam{
			AK: os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"),
			SK: os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
		},
	}

	res = append(res, testAccount)

	return res
}

func TestGetDomainData(t *testing.T) {
	p := schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.AlibabaCloud),
		Resources: []schema.Resource{
			GetDomainData(),
		},

		Service:              &collector.Services{},
		DefaultRegions:       []string{"cn-beijing"},
		DefaultCloudAccounts: GetTestAccount(),
	})

	if err := schema.RunExecutor(p); err != nil {
		log.GetWLogger().Error(err.Error())
	}
}
