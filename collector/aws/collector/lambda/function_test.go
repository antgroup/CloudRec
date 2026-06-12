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

// Streaming regression test for the "SDK paginator" collector form.
//
// Representative collector: lambda (this file). The primary list call is driven
// by an aws-sdk-go-v2 NewXPaginator. The same form backs these sibling
// collectors, covered here by representation: acm, eks, kms, secretsmanager,
// sns, sqs, route53/resourcerecordset. (A few, e.g. route53 hosted zones, page
// their outermost list with a manual token but keep the same per-page +
// per-item streaming shape.)
//
// Two streaming links are asserted:
//   - per-page list streaming: the first ListFunctions page is pushed before
//     the next page is fetched
//     (TestStreamFunctionsStreamsFirstPageBeforeNextPageList).
//   - per-item enrich streaming: the first function is pushed once its own
//     GetPolicy / ListFunctionURLConfigs / ListTags finish
//     (TestStreamFunctionsPushesFirstResultBeforeAllFunctionsFinish).
//
// This representation covers the shared streaming skeleton, not each sibling's
// own paginator input/termination or enrich sub-calls.
package lambda

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// fakeLambdaClient is a deterministic lambdaAPI stand-in. ListFunctions returns
// either a single page (functions) or a sequence of pages (pages, which takes
// precedence). Either the ListFunctions call or the per-function ListTags call
// can be made to block after a configured number of invocations, letting a test
// prove the first function is streamed before later work finishes.
type fakeLambdaClient struct {
	functions []types.FunctionConfiguration   // single-page mode
	pages     [][]types.FunctionConfiguration // multi-page mode (takes precedence)

	blockListFunctionsAfter int // block ListFunctions after this many calls
	unblockList             chan struct{}

	blockListTagsAfter int // block ListTags after this many calls
	unblockTags        chan struct{}

	mu                 sync.Mutex
	listFunctionsCalls int
	listTagsCalls      int
}

func (f *fakeLambdaClient) ListFunctions(ctx context.Context, _ *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	f.mu.Lock()
	f.listFunctionsCalls++
	call := f.listFunctionsCalls
	f.mu.Unlock()

	if f.blockListFunctionsAfter > 0 && call > f.blockListFunctionsAfter && f.unblockList != nil {
		select {
		case <-f.unblockList:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if len(f.pages) > 0 {
		idx := call - 1
		if idx >= len(f.pages) {
			return &lambda.ListFunctionsOutput{}, nil
		}
		output := &lambda.ListFunctionsOutput{Functions: f.pages[idx]}
		if idx < len(f.pages)-1 {
			output.NextMarker = aws.String(fmt.Sprintf("page-%d", call))
		}
		return output, nil
	}

	return &lambda.ListFunctionsOutput{Functions: f.functions}, nil
}

func (f *fakeLambdaClient) GetPolicy(context.Context, *lambda.GetPolicyInput, ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	return &lambda.GetPolicyOutput{Policy: aws.String("{}")}, nil
}

func (f *fakeLambdaClient) ListFunctionUrlConfigs(context.Context, *lambda.ListFunctionUrlConfigsInput, ...func(*lambda.Options)) (*lambda.ListFunctionUrlConfigsOutput, error) {
	return &lambda.ListFunctionUrlConfigsOutput{}, nil
}

func (f *fakeLambdaClient) ListTags(ctx context.Context, _ *lambda.ListTagsInput, _ ...func(*lambda.Options)) (*lambda.ListTagsOutput, error) {
	f.mu.Lock()
	f.listTagsCalls++
	call := f.listTagsCalls
	f.mu.Unlock()

	if f.blockListTagsAfter > 0 && call > f.blockListTagsAfter && f.unblockTags != nil {
		select {
		case <-f.unblockTags:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return &lambda.ListTagsOutput{Tags: map[string]string{"k": "v"}}, nil
}

// Property (a) — enrich streaming: the first function is pushed once its own
// GetPolicy / ListFunctionURLConfigs / ListTags calls return, without waiting
// for later functions. The second function's ListTags call is blocked, so a
// build-slice-then-push regression would never deliver the first result.
func TestStreamFunctionsPushesFirstResultBeforeAllFunctionsFinish(t *testing.T) {
	unblockTags := make(chan struct{})
	client := &fakeLambdaClient{
		functions:          makeFunctions(5),
		blockListTagsAfter: 1,
		unblockTags:        unblockTags,
	}
	res := make(chan any, len(client.functions))
	done := make(chan error, 1)

	go func() {
		done <- streamFunctions(context.Background(), client, res)
	}()

	detail := receiveFirstFunction(t, res)
	if detail.Function.FunctionName == nil {
		t.Fatal("function name is nil")
	}
	close(unblockTags)

	if err := <-done; err != nil {
		t.Fatalf("streamFunctions returned error: %v", err)
	}
	if got := 1 + len(res); got != len(client.functions) {
		t.Fatalf("streamed function count = %d, want %d", got, len(client.functions))
	}
}

// Property (b) — per-page streaming: the first ListFunctions page is pushed
// before the second page is even listed. The second list call is blocked, so
// an accumulate-all-pages-then-push regression would deadlock and never deliver
// the first result.
func TestStreamFunctionsStreamsFirstPageBeforeNextPageList(t *testing.T) {
	unblockList := make(chan struct{})
	page1, page2 := makeFunctions(2), makeFunctions(3)
	client := &fakeLambdaClient{
		pages:                   [][]types.FunctionConfiguration{page1, page2},
		blockListFunctionsAfter: 1,
		unblockList:             unblockList,
	}
	total := len(page1) + len(page2)
	res := make(chan any, total)
	done := make(chan error, 1)

	go func() {
		done <- streamFunctions(context.Background(), client, res)
	}()

	_ = receiveFirstFunction(t, res)
	close(unblockList)

	if err := <-done; err != nil {
		t.Fatalf("streamFunctions returned error: %v", err)
	}
	if got := 1 + len(res); got != total {
		t.Fatalf("streamed function count = %d, want %d", got, total)
	}
}

func receiveFirstFunction(t *testing.T, res <-chan any) *FunctionDetail {
	t.Helper()
	select {
	case got := <-res:
		detail, ok := got.(*FunctionDetail)
		if !ok {
			t.Fatalf("got %T, want *FunctionDetail", got)
		}
		return detail
	case <-time.After(time.Second):
		t.Fatal("collector did not stream first result before processing all functions")
	}
	return nil
}

func makeFunctions(count int) []types.FunctionConfiguration {
	functions := make([]types.FunctionConfiguration, 0, count)
	for i := 0; i < count; i++ {
		functions = append(functions, types.FunctionConfiguration{
			FunctionName: aws.String(fmt.Sprintf("fn-%d", i)),
			FunctionArn:  aws.String(fmt.Sprintf("arn:fn-%d", i)),
		})
	}
	return functions
}
