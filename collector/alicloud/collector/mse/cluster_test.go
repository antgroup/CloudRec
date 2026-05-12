package mse

import (
	"testing"

	mse20190531 "github.com/alibabacloud-go/mse-20190531/v5/client"
	"github.com/alibabacloud-go/tea/tea"
)

func TestMSEClusterID(t *testing.T) {
	cases := map[string]struct {
		cluster *mse20190531.ListClustersResponseBodyData
		want    string
	}{
		"nil cluster": {
			want: "",
		},
		"nil name": {
			cluster: &mse20190531.ListClustersResponseBodyData{},
			want:    "",
		},
		"standard name": {
			cluster: &mse20190531.ListClustersResponseBodyData{ClusterName: tea.String("prod-abc")},
			want:    "mse-abc",
		},
		"unexpected name": {
			cluster: &mse20190531.ListClustersResponseBodyData{ClusterName: tea.String("prod")},
			want:    "prod",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := mseClusterID(tc.cluster); got != tc.want {
				t.Fatalf("mseClusterID() = %q, want %q", got, tc.want)
			}
		})
	}
}
