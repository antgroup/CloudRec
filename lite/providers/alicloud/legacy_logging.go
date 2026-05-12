package alicloud

import (
	"fmt"
	"os"
	"strings"

	corelog "github.com/core-sdk/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	EnvCollectorLogLevel       = "CLOUDREC_LITE_COLLECTOR_LOG_LEVEL"
	collectorLogLevelConfigKey = "collector_log_level"
	defaultCollectorLogPath    = "./logs/cloudrec-lite-collector.log"
)

func configureLegacyCollectorLogging(accountConfig map[string]string) error {
	levelName := firstNonEmpty(
		stringFromStringMap(accountConfig, collectorLogLevelConfigKey, "collectorLogLevel"),
		os.Getenv(EnvCollectorLogLevel),
		"silent",
	)

	levelName = strings.ToLower(strings.TrimSpace(levelName))
	switch levelName {
	case "", "silent", "off", "none", "false":
		corelog.SetWLogger(zap.NewNop())
		return nil
	case "debug":
		corelog.SetWLogger(corelog.NewLogger(defaultCollectorLogPath, zapcore.DebugLevel, 256, 30, 7, true))
		return nil
	case "info":
		corelog.SetWLogger(corelog.NewLogger(defaultCollectorLogPath, zapcore.InfoLevel, 256, 30, 7, true))
		return nil
	case "warn", "warning":
		corelog.SetWLogger(corelog.NewLogger(defaultCollectorLogPath, zapcore.WarnLevel, 256, 30, 7, true))
		return nil
	case "error":
		corelog.SetWLogger(corelog.NewLogger(defaultCollectorLogPath, zapcore.ErrorLevel, 256, 30, 7, true))
		return nil
	default:
		return fmt.Errorf("invalid collector log level %q, want silent, error, warn, info, or debug", levelName)
	}
}
