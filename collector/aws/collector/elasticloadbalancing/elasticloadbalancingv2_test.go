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

package elasticloadbalancing

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

type fakeELBV2Client struct {
	loadBalancers    []types.LoadBalancer
	blockAfterCalls  int
	unblockListeners chan struct{}

	mu            sync.Mutex
	listenerCalls int
}

func (f *fakeELBV2Client) DescribeLoadBalancers(context.Context, *elasticloadbalancingv2.DescribeLoadBalancersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{
		LoadBalancers: f.loadBalancers,
	}, nil
}

func (f *fakeELBV2Client) DescribeListeners(ctx context.Context, input *elasticloadbalancingv2.DescribeListenersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	f.mu.Lock()
	f.listenerCalls++
	call := f.listenerCalls
	f.mu.Unlock()

	if f.blockAfterCalls > 0 && call > f.blockAfterCalls && f.unblockListeners != nil {
		select {
		case <-f.unblockListeners:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return &elasticloadbalancingv2.DescribeListenersOutput{
		Listeners: []types.Listener{
			{
				ListenerArn:     aws.String(fmt.Sprintf("listener-%d", call)),
				LoadBalancerArn: input.LoadBalancerArn,
				Port:            aws.Int32(80),
			},
		},
	}, nil
}

func TestStreamELBDetailsPushesFirstResultBeforeAllLoadBalancersFinish(t *testing.T) {
	unblockListeners := make(chan struct{})
	client := &fakeELBV2Client{
		loadBalancers:    makeLoadBalancers(5),
		blockAfterCalls:  1,
		unblockListeners: unblockListeners,
	}
	res := make(chan any, len(client.loadBalancers))
	done := make(chan error, 1)

	go func() {
		done <- streamELBDetails(context.Background(), client, res, nil, nil)
	}()

	got := receiveFirstResult(t, res)
	detail, ok := got.(ELBDetail)
	if !ok {
		t.Fatalf("got %T, want ELBDetail", got)
	}
	if len(detail.Listeners) != 1 {
		t.Fatalf("listener count = %d, want 1", len(detail.Listeners))
	}
	close(unblockListeners)

	if err := <-done; err != nil {
		t.Fatalf("streamELBDetails returned error: %v", err)
	}
	if got := 1 + len(res); got != len(client.loadBalancers) {
		t.Fatalf("streamed ELB detail count = %d, want %d", got, len(client.loadBalancers))
	}
}

func TestStreamELBListenersPushesFirstResultBeforeAllLoadBalancersFinish(t *testing.T) {
	unblockListeners := make(chan struct{})
	client := &fakeELBV2Client{
		loadBalancers:    makeLoadBalancers(5),
		blockAfterCalls:  1,
		unblockListeners: unblockListeners,
	}
	res := make(chan any, len(client.loadBalancers))
	done := make(chan error, 1)

	go func() {
		done <- streamELBListeners(context.Background(), client, res)
	}()

	got := receiveFirstResult(t, res)
	detail, ok := got.(ELBListenerDetail)
	if !ok {
		t.Fatalf("got %T, want ELBListenerDetail", got)
	}
	if detail.Listener.ListenerArn == nil {
		t.Fatal("listener arn is nil")
	}
	close(unblockListeners)

	if err := <-done; err != nil {
		t.Fatalf("streamELBListeners returned error: %v", err)
	}
	if got := 1 + len(res); got != len(client.loadBalancers) {
		t.Fatalf("streamed ELB listener count = %d, want %d", got, len(client.loadBalancers))
	}
}

func receiveFirstResult(t *testing.T, res <-chan any) any {
	t.Helper()
	select {
	case got := <-res:
		return got
	case <-time.After(time.Second):
		t.Fatal("collector did not stream first result before processing all load balancers")
	}
	return nil
}

func makeLoadBalancers(count int) []types.LoadBalancer {
	loadBalancers := make([]types.LoadBalancer, 0, count)
	for i := 0; i < count; i++ {
		loadBalancers = append(loadBalancers, types.LoadBalancer{
			LoadBalancerArn:  aws.String(fmt.Sprintf("lb-%d", i)),
			LoadBalancerName: aws.String(fmt.Sprintf("lb-%d", i)),
			SecurityGroups:   []string{fmt.Sprintf("sg-%d", i)},
			VpcId:            aws.String(fmt.Sprintf("vpc-%d", i)),
		})
	}
	return loadBalancers
}
