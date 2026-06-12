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

// Streaming regression test for the "manual pagination token" collector form.
//
// Representative collector: elasticloadbalancing / ELBv2 (this file). The
// primary list call (DescribeLoadBalancers) is paginated by hand over a
// next-token field, then each item is enriched and pushed. The same form — a
// hand-rolled list loop over NextMarker / Marker / NextToken / IsTruncated /
// ContinuationToken — backs these sibling collectors, covered here by
// representation: ec2 (ec2/security_group/vpc), ecr, efs, fsx, rds,
// route53/domain, s3, wafv2, iam.
//
// Two streaming links are asserted:
//   - per-page list streaming: the first list page is pushed before the next
//     page is fetched (TestStream*StreamsFirstPageBeforeNextPageList).
//   - per-item enrich streaming: the first item is pushed once its own enrich
//     calls finish, without waiting for later items
//     (TestStream*PushesFirstResultBeforeAllLoadBalancersFinish).
//
// This representation covers the shared streaming skeleton, not each sibling's
// own list-termination field or enrich sub-calls.
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

// fakeELBV2Client is a deterministic elbv2API stand-in. DescribeLoadBalancers
// returns either a single page (loadBalancers) or a sequence of pages (pages,
// which takes precedence). Either the list call or the per-LB listener call can
// be made to block after a configured number of invocations, letting a test
// prove the first result is streamed before later work finishes.
type fakeELBV2Client struct {
	loadBalancers []types.LoadBalancer   // single-page mode
	pages         [][]types.LoadBalancer // multi-page mode (takes precedence)

	blockListenersAfter int // block DescribeListeners after this many calls
	unblockListeners    chan struct{}

	blockListAfter int // block DescribeLoadBalancers after this many calls
	unblockList    chan struct{}

	mu            sync.Mutex
	listCalls     int
	listenerCalls int
}

func (f *fakeELBV2Client) DescribeLoadBalancers(ctx context.Context, _ *elasticloadbalancingv2.DescribeLoadBalancersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	f.mu.Lock()
	f.listCalls++
	call := f.listCalls
	f.mu.Unlock()

	if f.blockListAfter > 0 && call > f.blockListAfter && f.unblockList != nil {
		select {
		case <-f.unblockList:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if len(f.pages) > 0 {
		idx := call - 1
		if idx >= len(f.pages) {
			return &elasticloadbalancingv2.DescribeLoadBalancersOutput{}, nil
		}
		output := &elasticloadbalancingv2.DescribeLoadBalancersOutput{LoadBalancers: f.pages[idx]}
		if idx < len(f.pages)-1 {
			output.NextMarker = aws.String(fmt.Sprintf("page-%d", call))
		}
		return output, nil
	}

	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{LoadBalancers: f.loadBalancers}, nil
}

func (f *fakeELBV2Client) DescribeListeners(ctx context.Context, input *elasticloadbalancingv2.DescribeListenersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	f.mu.Lock()
	f.listenerCalls++
	call := f.listenerCalls
	f.mu.Unlock()

	if f.blockListenersAfter > 0 && call > f.blockListenersAfter && f.unblockListeners != nil {
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

// Property (a) — enrich streaming: the first LB is pushed once its own listener
// call returns, without waiting for later LBs' listener calls. The second
// listener call is blocked, so a build-slice-then-push regression would never
// deliver the first result.
func TestStreamELBDetailsPushesFirstResultBeforeAllLoadBalancersFinish(t *testing.T) {
	unblockListeners := make(chan struct{})
	client := &fakeELBV2Client{
		loadBalancers:       makeLoadBalancers(5),
		blockListenersAfter: 1,
		unblockListeners:    unblockListeners,
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
		loadBalancers:       makeLoadBalancers(5),
		blockListenersAfter: 1,
		unblockListeners:    unblockListeners,
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

// Property (b) — per-page streaming: the first DescribeLoadBalancers page is
// pushed before the second page is even listed. The second list call is
// blocked, so an accumulate-all-pages-then-push regression would deadlock and
// never deliver the first result.
func TestStreamELBListenersStreamsFirstPageBeforeNextPageList(t *testing.T) {
	unblockList := make(chan struct{})
	page1, page2 := makeLoadBalancers(2), makeLoadBalancers(3)
	client := &fakeELBV2Client{
		pages:          [][]types.LoadBalancer{page1, page2},
		blockListAfter: 1,
		unblockList:    unblockList,
	}
	total := len(page1) + len(page2)
	res := make(chan any, total)
	done := make(chan error, 1)

	go func() {
		done <- streamELBListeners(context.Background(), client, res)
	}()

	got := receiveFirstResult(t, res)
	if _, ok := got.(ELBListenerDetail); !ok {
		t.Fatalf("got %T, want ELBListenerDetail", got)
	}
	close(unblockList)

	if err := <-done; err != nil {
		t.Fatalf("streamELBListeners returned error: %v", err)
	}
	if got := 1 + len(res); got != total {
		t.Fatalf("streamed ELB listener count = %d, want %d", got, total)
	}
}

func TestStreamELBDetailsStreamsFirstPageBeforeNextPageList(t *testing.T) {
	unblockList := make(chan struct{})
	page1, page2 := makeLoadBalancers(2), makeLoadBalancers(3)
	client := &fakeELBV2Client{
		pages:          [][]types.LoadBalancer{page1, page2},
		blockListAfter: 1,
		unblockList:    unblockList,
	}
	total := len(page1) + len(page2)
	res := make(chan any, total)
	done := make(chan error, 1)

	go func() {
		done <- streamELBDetails(context.Background(), client, res, nil, nil)
	}()

	got := receiveFirstResult(t, res)
	if _, ok := got.(ELBDetail); !ok {
		t.Fatalf("got %T, want ELBDetail", got)
	}
	close(unblockList)

	if err := <-done; err != nil {
		t.Fatalf("streamELBDetails returned error: %v", err)
	}
	if got := 1 + len(res); got != total {
		t.Fatalf("streamed ELB detail count = %d, want %d", got, total)
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
