package apig

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/log"
	"github.com/core-sdk/schema"
	"context"
	apig20240327 "github.com/alibabacloud-go/apig-20240327/v3/client"
	"github.com/cloudrec/alicloud/collector"
	"go.uber.org/zap"
)

func GetDomainData() schema.Resource {
	return schema.Resource{
		ResourceType:      collector.APIG,
		ResourceTypeName:  collector.APIG,
		ResourceGroupType: constant.NET,
		Desc:              `https://apig.console.aliyun.com/?region=cn-beijing#/cn-beijing/gateway`,

		ResourceDetailFunc: ListApigDomains,

		// 使用json path 从detail中取值，其中只有ResourceId是必须的
		RowField: schema.RowField{
			ResourceId:   "$.Domain.domainId",
			ResourceName: "$.Domain.name",
		},
		Regions: []string{
			"cn-qingdao",
			"cn-beijing",
			"cn-zhangjiakou",
			"cn-wulanchabu",
			"cn-hangzhou",
			"cn-shanghai",
			"cn-shenzhen",
			"cn-heyuan",
			"cn-guangzhou",
			"ap-southeast-6",
			"ap-northeast-2",
			"ap-southeast-3",
			"ap-northeast-1",
			"ap-southeast-7",
			"cn-chengdu",
			"ap-southeast-1",
			"ap-southeast-5",
			"cn-hongkong",
			"eu-central-1",
			"us-east-1",
			"us-west-1",
			"eu-west-1",
			"me-east-1",
			"me-central-1",
		},
		Dimension: schema.Regional,
	}
}

type Detail struct {
	Domain *apig20240327.GetDomainResponseBodyData
}

func NewInt32Pointer(i int) *int32 {
	v := int32(i)
	return &v
}

func ListApigDomains(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	log.CtxLogger(ctx).Info("execute ListApigDomains start")
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
			log.CtxLogger(ctx).Warn("APIG domain ListDomainsRequest error:", zap.Error(err))
			return err
		}
		if len(response.Body.Data.Items) == 0 {
			return nil
		}

		for _, item := range response.Body.Data.Items {
			d := Detail{
				Domain: GetDomain(ctx, cli, item.DomainId),
			}
			res <- d
			count++
		}
		if int32(count) >= *response.Body.Data.TotalSize {
			break
		}
		pageNumber = int(pageNumber) + 1
	}
	return nil
}

func GetDomain(ctx context.Context, cli *apig20240327.Client, domainId *string) *apig20240327.GetDomainResponseBodyData {
	log.CtxLogger(ctx).Info("execute GetDomain start")
	req := &apig20240327.GetDomainRequest{}
	resp, err := cli.GetDomain(domainId, req)
	if err != nil {
		log.CtxLogger(ctx).Warn("APIG domain GetDomain error:", zap.Error(err))
		return nil
	}
	return resp.Body.Data
}
