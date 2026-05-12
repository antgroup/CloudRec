package dts

import "testing"

func TestNewDescribeMigrationJobsRequestUsesCorrectAction(t *testing.T) {
	request := newDescribeMigrationJobsRequest()

	if got := request.GetActionName(); got != "DescribeMigrationJobs" {
		t.Fatalf("action = %q, want DescribeMigrationJobs", got)
	}
}
