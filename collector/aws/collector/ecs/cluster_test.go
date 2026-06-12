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

// Streaming regression test for the "ARN list then batched describe" collector
// form.
//
// Representative collector: ecs (this file). listClusters paginates ARNs, then
// the ARNs are described in batches of 100 (API limit) and each described item
// is enriched and pushed. No other AWS collector currently shares this form;
// ecs is the sole representative.
//
// Two streaming links are asserted:
//   - per-batch streaming: the first DescribeClusters batch is pushed before
//     the next batch is described
//     (TestStreamClustersStreamsFirstBatchBeforeNextBatchDescribe).
//   - per-item enrich streaming: the first cluster is pushed once its own
//     ListServices / ListTasks finish
//     (TestStreamClustersPushesFirstResultBeforeAllClustersFinish).
package ecs

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// fakeECSClient is a deterministic ecsAPI stand-in. ListClusters returns every
// ARN in a single page; DescribeClusters echoes the requested ARNs back as
// clusters. Either the per-batch DescribeClusters call or the per-cluster
// ListServices enrichment call can be made to block after a configured number
// of invocations, letting a test prove the first cluster is streamed before
// later batches / clusters finish. DescribeServices / ListTasks / DescribeTasks
// return empty so enrichment stays cheap.
type fakeECSClient struct {
	clusterArns []string

	blockDescribeClustersAfter int // block DescribeClusters after this many calls (per-batch streaming)
	unblockDescribe            chan struct{}

	blockListServicesAfter int // block ListServices after this many calls (per-cluster streaming)
	unblockServices        chan struct{}

	mu                    sync.Mutex
	listClustersCalls     int
	describeClustersCalls int
	listServicesCalls     int
}

func (f *fakeECSClient) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	f.mu.Lock()
	f.listClustersCalls++
	f.mu.Unlock()
	return &ecs.ListClustersOutput{ClusterArns: f.clusterArns}, nil
}

func (f *fakeECSClient) DescribeClusters(ctx context.Context, input *ecs.DescribeClustersInput, _ ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
	f.mu.Lock()
	f.describeClustersCalls++
	call := f.describeClustersCalls
	f.mu.Unlock()

	if f.blockDescribeClustersAfter > 0 && call > f.blockDescribeClustersAfter && f.unblockDescribe != nil {
		select {
		case <-f.unblockDescribe:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	clusters := make([]types.Cluster, 0, len(input.Clusters))
	for _, arn := range input.Clusters {
		clusters = append(clusters, types.Cluster{
			ClusterArn:  aws.String(arn),
			ClusterName: aws.String(arn),
		})
	}
	return &ecs.DescribeClustersOutput{Clusters: clusters}, nil
}

func (f *fakeECSClient) ListServices(ctx context.Context, _ *ecs.ListServicesInput, _ ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	f.mu.Lock()
	f.listServicesCalls++
	call := f.listServicesCalls
	f.mu.Unlock()

	if f.blockListServicesAfter > 0 && call > f.blockListServicesAfter && f.unblockServices != nil {
		select {
		case <-f.unblockServices:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return &ecs.ListServicesOutput{}, nil
}

func (f *fakeECSClient) DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	return &ecs.DescribeServicesOutput{}, nil
}

func (f *fakeECSClient) ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{}, nil
}

func (f *fakeECSClient) DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{}, nil
}

// Property (a) — enrich streaming: the first cluster is pushed once its own
// ListServices / ListTasks calls return, without waiting for later clusters.
// The second cluster's ListServices call is blocked, so a build-slice-then-push
// regression would never deliver the first result.
func TestStreamClustersPushesFirstResultBeforeAllClustersFinish(t *testing.T) {
	unblockServices := make(chan struct{})
	arns := makeClusterArns(5)
	client := &fakeECSClient{
		clusterArns:            arns,
		blockListServicesAfter: 1,
		unblockServices:        unblockServices,
	}
	res := make(chan any, len(arns))
	done := make(chan error, 1)

	go func() {
		done <- streamClusters(context.Background(), client, res)
	}()

	detail := receiveFirstCluster(t, res)
	if detail.Cluster.ClusterArn == nil {
		t.Fatal("cluster arn is nil")
	}
	close(unblockServices)

	if err := <-done; err != nil {
		t.Fatalf("streamClusters returned error: %v", err)
	}
	if got := 1 + len(res); got != len(arns) {
		t.Fatalf("streamed cluster count = %d, want %d", got, len(arns))
	}
}

// Property (b) — per-batch streaming: the first DescribeClusters batch is pushed
// before the second batch is described. With more than 100 ARNs the collector
// describes in two batches; the second DescribeClusters call is blocked, so an
// accumulate-all-batches-then-push regression would deadlock and never deliver
// the first result.
func TestStreamClustersStreamsFirstBatchBeforeNextBatchDescribe(t *testing.T) {
	unblockDescribe := make(chan struct{})
	arns := makeClusterArns(150) // 100 + 50 => two DescribeClusters batches
	client := &fakeECSClient{
		clusterArns:                arns,
		blockDescribeClustersAfter: 1,
		unblockDescribe:            unblockDescribe,
	}
	res := make(chan any, len(arns))
	done := make(chan error, 1)

	go func() {
		done <- streamClusters(context.Background(), client, res)
	}()

	_ = receiveFirstCluster(t, res)
	close(unblockDescribe)

	if err := <-done; err != nil {
		t.Fatalf("streamClusters returned error: %v", err)
	}
	if got := 1 + len(res); got != len(arns) {
		t.Fatalf("streamed cluster count = %d, want %d", got, len(arns))
	}
}

func receiveFirstCluster(t *testing.T, res <-chan any) *ClusterDetail {
	t.Helper()
	select {
	case got := <-res:
		detail, ok := got.(*ClusterDetail)
		if !ok {
			t.Fatalf("got %T, want *ClusterDetail", got)
		}
		return detail
	case <-time.After(time.Second):
		t.Fatal("collector did not stream first result before processing all clusters")
	}
	return nil
}

func makeClusterArns(count int) []string {
	arns := make([]string, 0, count)
	for i := 0; i < count; i++ {
		arns = append(arns, fmt.Sprintf("arn:cluster-%d", i))
	}
	return arns
}
