package cloudfw

import (
	"context"
	"reflect"
	"strconv"
	"testing"
	"time"

	cloudfw20171207 "github.com/alibabacloud-go/cloudfw-20171207/v8/client"
)

func TestCollectControlPoliciesCollectsInAndOutDirections(t *testing.T) {
	pages := map[string]map[int][]*cloudfw20171207.DescribeControlPolicyResponseBodyPolicys{
		"in": {
			1: {
				{AclUuid: stringPtr("in-1")},
				{AclUuid: stringPtr("in-2")},
			},
			2: {
				{AclUuid: stringPtr("in-3")},
			},
		},
		"out": {
			1: {
				{AclUuid: stringPtr("out-1")},
			},
		},
	}
	totals := map[string]int{
		"in":  3,
		"out": 1,
	}

	var calls []string
	var emitted []string
	err := collectControlPolicies(context.Background(), []string{"in", "out"}, 2, func(direction string, page int, size int) ([]*cloudfw20171207.DescribeControlPolicyResponseBodyPolicys, int, error) {
		calls = append(calls, direction+":"+strconv.Itoa(page)+":"+strconv.Itoa(size))
		return pages[direction][page], totals[direction], nil
	}, func(policy *cloudfw20171207.DescribeControlPolicyResponseBodyPolicys) {
		emitted = append(emitted, *policy.AclUuid)
	}, func(time.Duration) {})
	if err != nil {
		t.Fatalf("collectControlPolicies() error = %v", err)
	}

	wantCalls := []string{"in:1:2", "in:2:2", "out:1:2"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	wantEmitted := []string{"in-1", "in-2", "in-3", "out-1"}
	if !reflect.DeepEqual(emitted, wantEmitted) {
		t.Fatalf("emitted = %#v, want %#v", emitted, wantEmitted)
	}
}

func stringPtr(value string) *string {
	return &value
}
