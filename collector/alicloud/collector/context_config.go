package collector

import (
	"context"
	"strings"

	"github.com/core-sdk/constant"
)

func ContextConfigValue(ctx context.Context, keys ...string) string {
	if ctx == nil {
		return ""
	}
	config, _ := ctx.Value(constant.CloudAccountConfig).(map[string]string)
	if len(config) == 0 {
		return ""
	}
	for _, key := range keys {
		if value := strings.TrimSpace(config[key]); value != "" {
			return value
		}
	}
	return ""
}
