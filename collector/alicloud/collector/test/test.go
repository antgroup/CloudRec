// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test

import (
	"github.com/core-sdk/constant"
	"github.com/core-sdk/schema"
	"context"
	"fmt"
	"time"
)

func TestBlockResource() schema.Resource {
	return schema.Resource{
		ResourceType:                 "TEST",
		ResourceTypeName:             "TEST",
		ResourceGroupType:            constant.NET,
		Desc:                         `https://api.aliyun.com/api/Cloudfw/2017-12-07/DescribeAssetList?tab=DEBUG&params={%22CurrentPage%22:%221%22,%22PageSize%22:%22100%22}`,
		ResourceDetailFuncWithCancel: TestBlock,
		Dimension:                    schema.Regional,
	}
}

func TestBlockResource2() schema.Resource {
	return schema.Resource{
		ResourceType:       "TEST",
		ResourceTypeName:   "TEST",
		ResourceGroupType:  constant.NET,
		Desc:               `https://api.aliyun.com/api/Cloudfw/2017-12-07/DescribeAssetList?tab=DEBUG&params={%22CurrentPage%22:%221%22,%22PageSize%22:%22100%22}`,
		ResourceDetailFunc: TestBlock2,
		Dimension:          schema.Regional,
	}
}

func TestTimeOutResource() schema.Resource {
	return schema.Resource{
		ResourceType:                 "TEST",
		ResourceTypeName:             "TEST",
		ResourceGroupType:            constant.NET,
		Desc:                         `https://api.aliyun.com/api/Cloudfw/2017-12-07/DescribeAssetList?tab=DEBUG&params={%22CurrentPage%22:%221%22,%22PageSize%22:%22100%22}`,
		ResourceDetailFuncWithCancel: TestTimeOut,
		Dimension:                    schema.Regional,
	}
}

func TestAutoExitResource() schema.Resource {
	return schema.Resource{
		ResourceType:                 "TEST",
		ResourceTypeName:             "TEST",
		ResourceGroupType:            constant.NET,
		Desc:                         `https://api.aliyun.com/api/Cloudfw/2017-12-07/DescribeAssetList?tab=DEBUG&params={%22CurrentPage%22:%221%22,%22PageSize%22:%22100%22}`,
		ResourceDetailFuncWithCancel: TestAutoExit,
		Dimension:                    schema.Regional,
	}
}

// TestTimeOut 测试超时退出
func TestTimeOut(ctx context.Context, cancel context.CancelFunc, service schema.ServiceInterface, res chan<- any) error {
	i := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Timeout......")
			return nil
		default:
			i++
			doSomeThing()
			fmt.Println(fmt.Sprintf("current time %d s...", i))
		}
	}

	return nil
}

// TestAutoExit 测试自动退出
func TestAutoExit(ctx context.Context, cancel context.CancelFunc, service schema.ServiceInterface, res chan<- any) error {
	i := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Println("Timeout......")
			return nil
		default:
			i++
			doSomeThing()
			fmt.Println(fmt.Sprintf("current time %d s...", i))
			if i == 10 {
				fmt.Println("application will now exit")
				cancel()
				return nil
			}
		}
	}

	return nil
}

// TestBlock 测试阻塞，此函数不执行完成，该周期不会完成
func TestBlock(ctx context.Context, cancel context.CancelFunc, service schema.ServiceInterface, res chan<- any) error {
	i := 0
	for {
		i++
		doSomeThing()
		fmt.Println(fmt.Sprintf("current time %d s...", i))
	}

	return nil
}

func TestBlock2(ctx context.Context, service schema.ServiceInterface, res chan<- any) error {
	i := 0
	for {
		i++
		doSomeThing()
		fmt.Println(fmt.Sprintf("current time %d s...", i))
	}

	return nil
}

func doSomeThing() {
	fmt.Println("doSomeThing")
	time.Sleep(1 * time.Second)
}
