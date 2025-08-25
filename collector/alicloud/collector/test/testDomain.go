package test

import (
	"context"
	"fmt"
	apig20240327 "github.com/alibabacloud-go/apig-20240327/v3/client"
	"github.com/cloudrec/alicloud/collector"
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"go.uber.org/zap"
)

//func main() {
//	p := schema.GetInstance(schema.PlatformConfig{
//		Name: string(constant.AlibabaCloud),
//		Resources: []schema.Resource{
//			GetDomainData(),
//		},
//
//		Service:        &collector.Services{},
//		DefaultRegions: []string{"cn-beijing"},
//	})
//
//	if err := schema.RunExecutor(p); err != nil {
//		log.GetWLogger().Error(err.Error())
//	}
//}

func GetDomainData() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.APIG,
		ResourceTypeName:  collector.APIG,
		ResourceGroupType: constant.NET,
		Desc:              `https://apig.console.aliyun.com/?region=cn-beijing#/cn-beijing/gateway`,

		ResourceDetailFunc: ListApigDomains,

		// 使用json path 从detail中取值，其中只有ResourceId是必须的
		RowField: schema.RowField{
			ResourceId:   "$.GetDomainResponseBodyData.DomainId",
			ResourceName: "$.GetDomainResponseBodyData.Name",
		},

		Dimension: schema.Regional,
	}
}

type DomainDetail struct {
	GetDomainResponseBodyData *apig20240327.GetDomainResponseBodyData
}

func DomainNewInt32Pointer(i int) *int32 {
	v := int32(i)
	return &v
}

func ListApigDomains(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	cli := service.(*collector.Services).APIG
	var pageNumber = 1
	count := 0
	for {
		req := &apig20240327.ListDomainsRequest{
			PageNumber: NewInt32Pointer(pageNumber),
			PageSize:   NewInt32Pointer(100),
		}
		response, err := cli.ListDomains(req)
		if err != nil {
			log.CtxLogger(ctx).Warn("APIG domain ListDomainsRequest error", zap.Error(err))
			return err
		}
		if len(response.Body.Data.Items) == 0 {
			return nil
		}

		for _, item := range response.Body.Data.Items {
			detail := DomainDetail{
				GetDomainResponseBodyData: GetDomain(ctx, cli, item.DomainId),
			}
			res <- detail
			count++

			// 打印 GetDomainResponseBodyData 的所有字段及其值
			data := detail.GetDomainResponseBodyData
			fmt.Printf("%+v\n", data)
		}
		if int32(count) >= *response.Body.Data.TotalSize {
			break
		}
		pageNumber = int(pageNumber) + 1
	}
	println(count)
	return nil
}

func GetDomain(ctx context.Context, cli *apig20240327.Client, domainId *string) *apig20240327.GetDomainResponseBodyData {
	req := &apig20240327.GetDomainRequest{}
	resp, err := cli.GetDomain(domainId, req)
	if err != nil {
		log.CtxLogger(ctx).Warn("APIG domain GetDomain error", zap.Error(err))
		return nil
	}
	return resp.Body.Data
}
