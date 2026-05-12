package bpstudio

import "testing"

func TestNewListApplicationRequestStartsAtFirstPage(t *testing.T) {
	request := newListApplicationRequest()

	if got := string(request.NextToken); got != "1" {
		t.Fatalf("NextToken = %q, want 1", got)
	}
	if got := string(request.MaxResults); got != "20" {
		t.Fatalf("MaxResults = %q, want 20", got)
	}
}
