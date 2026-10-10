# How to Test

# Unit Test 
<font style="color:rgb(24, 32, 38);">Using the AK and SK entered in the code, instead of getting them from the Server, you can use this method for unit testing. The data will not be transmitted to the Server, but the result json will be printed at the terminal. </font>

> <font style="color:rgb(24, 32, 38);">It is strongly recommended that the access key be placed in a local environment variable </font>
>

```go
import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"test/provider"
	"testing"
)

var GetTestAccount = func() (res []schema.CloudAccount) {
    testAccount := schema.CloudAccount{
        CloudAccountId: "you need input your CloudAccountId",
        AK:             "os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")",
        SK:             "os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")",
    }

    res = append(res, testAccount)

    return res
}


// TestGetEcsData Test to get ecs instance data, normal case
func TestGetEcsData(t *testing.T) {

    p := schema.GetInstance(schema.PlatformConfig{
        Name: string(constant.AlibabaCloud),
        Resources: []schema.Resource{
            GetEcsData(),
        },

        Service:              &provider.Services{},
        DefaultRegions:       []string{"cn-hangzhou"},
        DefaultCloudAccounts: GetTestAccount(),
    })

    if err := schema.RunExecutor(p); err != nil {
        log.GetWLogger().Error(err.Error())
    }
}


// TestGetEcsDataUserErrRegions Test to get ecs instance data, abnormal case use not exist region
func TestGetEcsDataUserErrRegions(t *testing.T) {

    p := schema.GetInstance(schema.PlatformConfig{
        Name: string(constant.AlibabaCloud),
        Resources: []schema.Resource{
            GetEcsData(),
        },

        Service:              &provider.Services{},
        DefaultRegions:       []string{"cn-hangzhou-not-exist"},
        DefaultCloudAccounts: GetTestAccount(),
    })

    if err := schema.RunExecutor(p); err != nil {
        log.GetWLogger().Error(err.Error())
    }
}
```

sample code:`/test/provider/ecs ecs_test.go` in the root directory 

# Integration Test 
<font style="color:rgb(24, 32, 38);">Assuming that the current platform has a main function, you need to put the new asset collection function into Resources. </font>

```go
package main

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"test/provider"
)
func main() {
	p := schema.GetInstance(schema.PlatformConfig{
		Name: string(constant.AlibabaCloud),
		Resources: []schema.Resource{
			GetEcsData(),
		},

		Service:        &provider.Services{},
		DefaultRegions: []string{"cn-hangzhou"},
	})

	if err := schema.RunExecutor(p); err != nil {
		log.GetWLogger().Error(err.Error())
	}
}


type Detail struct {
	Instance ecs.Instance
}

func GetEcsData() schema.Resource {
	return schema.Resource{
		ResourceType:     "ECS",
		ResourceTypeName: "ECS",
		Desc:             ``,
		ResourceDetailFunc: func(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
			client := service.(*provider.Services).ECS
			req := ecs.CreateDescribeInstancesRequest()
			req.PageSize = requests.NewInteger(50)
			req.PageNumber = requests.NewInteger(1)
			req.Scheme = "HTTPS"
			req.QueryParams["product"] = "Ecs"

			count := 0
			for {
				response, err := client.DescribeInstances(req)
				if err != nil {
					return err
				}
				for _, i := range response.Instances.Instance {
					d := Detail{
						Instance: i,
					}

					res <- d
					count++
				}
				if count >= response.TotalCount {
					break
				}
				req.PageNumber = requests.NewInteger(response.PageNumber + 1)
			}

			return nil
		},
		RowField: schema.RowField{
			ResourceId:   "$.Instance.InstanceId",
			ResourceName: "$.Instance.InstanceName",
		},
		Dimension: schema.Regional,
	}
}
```

Make sure your Server is up and available.

<font style="color:rgb(24, 32, 38);">Run </font>`<font style="color:rgb(24, 32, 38);">main.go</font>`<font style="color:rgb(24, 32, 38);">. Check whether config.yaml exists in the root directory of the project. If it does not exist, you need to create and check the configuration items in it, and you need to modify the configuration to the configuration you expect, especially to get the correct accessstoken, otherwise the data will not be submitted to the Server. </font>

```yaml
# Collector name, if not configured, hostname will be used
AgentName: "Test Collector"
# The server URL, http://localhost:8080 is used by default, and can be adjusted according to actual conditions
ServerUrl: "http://localhost:8080"

# eg：@every 30s、@every 5m、@every 1h
# @every 5m means obtaining an account every five minutes. If the current task is finished, skip this task.
Cron: "@every 5m"

# If RunOnlyOnce is set to false, the program will be executed once immediately, but the program will not exit. It will be run regularly according to the Cron cycle.
# If RunOnlyOnce is set to true, the program will be executed once immediately and then exit.
RunOnlyOnce: false

# Access token, which is used to authenticate the request. You can get it from the server
AccessToken: "change your access token"
```


