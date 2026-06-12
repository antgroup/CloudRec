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

// Streaming regression test for the "un-paginated list" collector form.
//
// Representative collector: opensearch (this file). ListDomainNames returns
// every domain in a single call, so — unlike the paginator and manual-token
// forms — there is no per-page list pagination to stream. The streaming
// guarantees this form must keep are therefore:
//
//   - per-item enrich streaming: the first domain is pushed as soon as its own
//     DescribeDomain call finishes, without waiting for later domains.
//   - failure isolation: a single domain whose DescribeDomain fails is skipped
//     (describeDomain returns nil and streamDomains continues) so one failure
//     neither panics nor aborts the rest of the region. This locks the bug fix
//     in commit 65e81d7.
//
// No other AWS collector currently shares this un-paginated form; opensearch is
// the sole representative.
package opensearch

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/opensearch/types"
)

// fakeOpenSearchClient is a deterministic opensearchAPI stand-in. ListDomainNames
// returns every domain at once; DescribeDomain echoes a status back per domain
// but can be made to block after a configured number of calls (per-item enrich
// streaming) or to fail for one named domain (failure isolation).
type fakeOpenSearchClient struct {
	domains []types.DomainInfo

	blockDescribeAfter int // block DescribeDomain after this many calls
	unblockDescribe    chan struct{}

	failDescribeName string // DescribeDomain returns an error for this domain name

	mu            sync.Mutex
	describeCalls int
}

func (f *fakeOpenSearchClient) ListDomainNames(context.Context, *opensearch.ListDomainNamesInput, ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	return &opensearch.ListDomainNamesOutput{DomainNames: f.domains}, nil
}

func (f *fakeOpenSearchClient) DescribeDomain(ctx context.Context, input *opensearch.DescribeDomainInput, _ ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error) {
	f.mu.Lock()
	f.describeCalls++
	call := f.describeCalls
	f.mu.Unlock()

	if f.blockDescribeAfter > 0 && call > f.blockDescribeAfter && f.unblockDescribe != nil {
		select {
		case <-f.unblockDescribe:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	name := aws.ToString(input.DomainName)
	if f.failDescribeName != "" && name == f.failDescribeName {
		return nil, fmt.Errorf("describe failed for %s", name)
	}

	return &opensearch.DescribeDomainOutput{
		DomainStatus: &types.DomainStatus{
			DomainName: input.DomainName,
			DomainId:   aws.String(name),
		},
	}, nil
}

// per-item enrich streaming: the first domain is pushed once its own
// DescribeDomain returns, without waiting for later domains. The second
// DescribeDomain call is blocked, so a build-slice-then-push regression would
// never deliver the first result.
func TestStreamDomainsPushesFirstResultBeforeAllDomainsFinish(t *testing.T) {
	unblock := make(chan struct{})
	client := &fakeOpenSearchClient{
		domains:            makeDomains(5),
		blockDescribeAfter: 1,
		unblockDescribe:    unblock,
	}
	res := make(chan any, len(client.domains))
	done := make(chan error, 1)

	go func() {
		done <- streamDomains(context.Background(), client, res)
	}()

	detail := receiveFirstDomain(t, res)
	if detail.DomainStatus == nil {
		t.Fatal("domain status is nil")
	}
	close(unblock)

	if err := <-done; err != nil {
		t.Fatalf("streamDomains returned error: %v", err)
	}
	if got := 1 + len(res); got != len(client.domains) {
		t.Fatalf("streamed domain count = %d, want %d", got, len(client.domains))
	}
}

// failure isolation: one domain whose DescribeDomain fails is skipped without
// panicking, and the remaining domains still stream. Removing the nil guard in
// streamDomains makes this dereference a nil DescribeDomainOutput and panic,
// regressing commit 65e81d7.
func TestStreamDomainsSkipsFailedDescribeWithoutPanic(t *testing.T) {
	client := &fakeOpenSearchClient{
		domains:          makeDomains(3),
		failDescribeName: "domain-1", // the middle domain's DescribeDomain fails
	}
	res := make(chan any, len(client.domains))

	if err := streamDomains(context.Background(), client, res); err != nil {
		t.Fatalf("streamDomains returned error: %v", err)
	}
	close(res)

	var got []DomainDetail
	for d := range res {
		detail, ok := d.(DomainDetail)
		if !ok {
			t.Fatalf("got %T, want DomainDetail", d)
		}
		got = append(got, detail)
	}
	if len(got) != 2 {
		t.Fatalf("streamed domain count = %d, want 2 (one DescribeDomain failure skipped)", len(got))
	}
	for _, d := range got {
		if aws.ToString(d.DomainStatus.DomainName) == "domain-1" {
			t.Fatal("failed domain leaked into results")
		}
	}
}

func receiveFirstDomain(t *testing.T, res <-chan any) DomainDetail {
	t.Helper()
	select {
	case got := <-res:
		detail, ok := got.(DomainDetail)
		if !ok {
			t.Fatalf("got %T, want DomainDetail", got)
		}
		return detail
	case <-time.After(time.Second):
		t.Fatal("collector did not stream first result before processing all domains")
	}
	return DomainDetail{}
}

func makeDomains(count int) []types.DomainInfo {
	domains := make([]types.DomainInfo, 0, count)
	for i := 0; i < count; i++ {
		domains = append(domains, types.DomainInfo{
			DomainName: aws.String(fmt.Sprintf("domain-%d", i)),
		})
	}
	return domains
}
