package alicloud

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/antgroup/CloudRec/lite/internal/provider"
	legacycollector "github.com/cloudrec/alicloud/collector"
)

type AccountValidator interface {
	Validate(context.Context, provider.Account, Credentials) error
}

type IMSAccountValidator struct{}

func (IMSAccountValidator) Validate(ctx context.Context, account provider.Account, credentials Credentials) error {
	if credentials.SecurityToken != "" {
		return errors.New("sts security token validation is not supported by the legacy collector yet; use long-lived test AK/SK or --skip-account-validation")
	}

	service := &legacycollector.Services{}
	param := legacyCloudAccountParam(account, credentials, legacycollector.Account, firstNonEmpty(credentials.Region, "cn-hangzhou"))
	if err := service.InitServices(param); err != nil {
		return classifyValidationError(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := service.IMS.GetAccountSummary()
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			return classifyValidationError(err)
		}
		return nil
	}
}

func classifyValidationError(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "invalidaccesskeyid") ||
		strings.Contains(lower, "signature") ||
		strings.Contains(lower, "forbidden.ram") ||
		strings.Contains(lower, "invalid credentials"):
		return fmt.Errorf("invalid_credentials: %w", err)
	case strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "not authorized") ||
		strings.Contains(lower, "denied") ||
		strings.Contains(lower, "no permission"):
		return fmt.Errorf("permission_denied: %w", err)
	case strings.Contains(lower, "timeout") ||
		strings.Contains(lower, "deadline") ||
		strings.Contains(lower, "connection") ||
		strings.Contains(lower, "i/o timeout"):
		return fmt.Errorf("network_error: %w", err)
	default:
		return fmt.Errorf("validation_error: %w", err)
	}
}
