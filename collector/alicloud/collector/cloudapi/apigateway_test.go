package cloudapi

import (
	"context"
	"testing"

	cloudapi20160714 "github.com/alibabacloud-go/cloudapi-20160714/v5/client"
	"github.com/alibabacloud-go/tea/tea"
)

func TestDescribeAPIsPageSummariesAllowsEmptySummarys(t *testing.T) {
	if got := describeAPIsPageSummaries(nil); len(got) != 0 {
		t.Fatalf("nil body summaries = %d, want 0", len(got))
	}

	if got := describeAPIsPageSummaries(&cloudapi20160714.DescribeApisResponseBody{}); len(got) != 0 {
		t.Fatalf("nil ApiSummarys summaries = %d, want 0", len(got))
	}

	body := &cloudapi20160714.DescribeApisResponseBody{
		ApiSummarys: &cloudapi20160714.DescribeApisResponseBodyApiSummarys{
			ApiSummary: []*cloudapi20160714.DescribeApisResponseBodyApiSummarysApiSummary{
				{ApiId: tea.String("api-1")},
			},
		},
	}
	got := describeAPIsPageSummaries(body)
	if len(got) != 1 || tea.StringValue(got[0].ApiId) != "api-1" {
		t.Fatalf("summaries = %#v, want api-1", got)
	}
}

func TestDescribeAPISkipsMissingInputs(t *testing.T) {
	if got := describeAPI(context.Background(), nil, nil); got != nil {
		t.Fatalf("describeAPI with nil inputs = %#v, want nil", got)
	}

	if got := describeAPI(context.Background(), nil, &cloudapi20160714.DescribeApisResponseBodyApiSummarysApiSummary{}); got != nil {
		t.Fatalf("describeAPI with missing api id = %#v, want nil", got)
	}
}
