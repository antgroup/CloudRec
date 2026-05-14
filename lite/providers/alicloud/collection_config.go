package alicloud

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	EnvCollectorTimeout           = "CLOUDREC_LITE_COLLECTOR_TIMEOUT"
	EnvCollectorConcurrency       = "CLOUDREC_LITE_COLLECTOR_CONCURRENCY"
	collectorTimeoutConfigKey     = "collector_timeout"
	collectorConcurrencyConfigKey = "collector_concurrency"
	defaultCollectorConcurrency   = 4
)

func collectorTimeout(config map[string]string, fallback time.Duration) (time.Duration, error) {
	value := firstNonEmpty(
		stringFromStringMap(config, collectorTimeoutConfigKey, "collectorTimeout"),
		os.Getenv(EnvCollectorTimeout),
	)
	if value == "" {
		return fallback, nil
	}

	timeout, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid collector timeout %q: %w", value, err)
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("invalid collector timeout %q: must be greater than 0", value)
	}
	return timeout, nil
}

func collectorConcurrency(config map[string]string, fallback int) (int, error) {
	value := firstNonEmpty(
		stringFromStringMap(config, collectorConcurrencyConfigKey, "collectorConcurrency"),
		os.Getenv(EnvCollectorConcurrency),
	)
	if value == "" {
		if fallback > 0 {
			return fallback, nil
		}
		return defaultCollectorConcurrency, nil
	}

	concurrency, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid collector concurrency %q: %w", value, err)
	}
	if concurrency <= 0 {
		return 0, fmt.Errorf("invalid collector concurrency %q: must be greater than 0", value)
	}
	return concurrency, nil
}
