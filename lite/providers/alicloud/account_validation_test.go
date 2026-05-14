package alicloud

import (
	"context"
	"errors"
	"strings"
	"testing"

	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
)

func TestIMSAccountValidatorRejectsSecurityTokenUntilLegacySupportsSTS(t *testing.T) {
	err := IMSAccountValidator{}.Validate(context.Background(), liteprovider.Account{
		AccountID: "123456789",
	}, Credentials{
		AccessKeyID:     "ak",
		AccessKeySecret: "sk",
		SecurityToken:   "token",
		Region:          "cn-hangzhou",
	})
	if err == nil || !strings.Contains(err.Error(), "sts security token validation is not supported") {
		t.Fatalf("error = %v, want sts unsupported error", err)
	}
}

func TestClassifyValidationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "invalid", err: errors.New("InvalidAccessKeyId.NotFound"), want: "invalid_credentials"},
		{name: "permission", err: errors.New("Forbidden: no permission"), want: "permission_denied"},
		{name: "network", err: errors.New("i/o timeout"), want: "network_error"},
		{name: "unknown", err: errors.New("other"), want: "validation_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classifyValidationError(tt.err)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Fatalf("error = %v, want prefix %q", err, tt.want)
			}
		})
	}
}
