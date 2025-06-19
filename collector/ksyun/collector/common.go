package collector

import (
	"context"
	"errors"
	"github.com/core-sdk/log"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"strings"
)

func ShowResponse(ctx context.Context, msg, apiName, responseStr string) {
	log.CtxLogger(ctx).Debug(msg, zap.String("apiName", apiName), zap.String("responseStr", responseStr))
}

func CheckError(responseStr string) error {
	if !strings.HasPrefix(responseStr, "{") && !strings.HasSuffix(responseStr, "}") {
		return errors.New(responseStr)
	}
	errObj := gjson.Get(responseStr, "Error")
	if errObj.Exists() {
		return errors.New(errObj.Raw)
	}
	return nil
}
