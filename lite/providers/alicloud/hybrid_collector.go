package alicloud

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/provider"
)

type HybridCollector struct {
	native *RegistryCollector
	legacy Collector
}

func NewHybridCollector(native *RegistryCollector, legacy Collector) *HybridCollector {
	return &HybridCollector{
		native: native,
		legacy: legacy,
	}
}

func (c *HybridCollector) Collect(ctx context.Context, account provider.Account, credentials Credentials) ([]provider.Asset, error) {
	specs := specsForAccount(account)
	if len(specs) == 0 {
		return nil, ErrSDKCollectionNotImplemented
	}

	var nativeTypes []string
	var legacyTypes []string
	for _, spec := range specs {
		if c.native != nil && c.native.HasAdapter(spec.Type) {
			nativeTypes = append(nativeTypes, spec.Type)
			continue
		}
		legacyTypes = append(legacyTypes, spec.Type)
	}

	var (
		assets   []provider.Asset
		failures []provider.CollectionFailure
	)
	collected, err := c.collectTypes(ctx, c.native, account, credentials, nativeTypes)
	assets = append(assets, collected...)
	failures = append(failures, failuresFromCollectorError(err, nativeTypes)...)

	collected, err = c.collectTypes(ctx, c.legacy, account, credentials, legacyTypes)
	assets = append(assets, collected...)
	failures = append(failures, failuresFromCollectorError(err, legacyTypes)...)

	if len(failures) > 0 {
		return assets, &provider.PartialCollectionError{
			Assets:   assets,
			Failures: failures,
		}
	}
	return assets, nil
}

func (c *HybridCollector) collectTypes(ctx context.Context, collector Collector, account provider.Account, credentials Credentials, resourceTypes []string) ([]provider.Asset, error) {
	if collector == nil || len(resourceTypes) == 0 {
		return nil, nil
	}
	next := account
	next.Config = cloneStringConfig(account.Config)
	next.Config["resource_types"] = strings.Join(resourceTypes, ",")
	return collector.Collect(ctx, next, credentials)
}

func failuresFromCollectorError(err error, resourceTypes []string) []provider.CollectionFailure {
	if err == nil {
		return nil
	}
	if partial, ok := asPartialCollectionError(err); ok {
		return partial.Failures
	}
	return []provider.CollectionFailure{{
		ResourceType: strings.Join(resourceTypes, ","),
		Category:     classifyCollectionError(err),
		Message:      sanitizeCollectionMessage(err.Error()),
	}}
}

func cloneStringConfig(input map[string]string) map[string]string {
	output := make(map[string]string, len(input)+1)
	for key, value := range input {
		output[key] = value
	}
	return output
}

func partialCollectionError(assets []provider.Asset, failures []provider.CollectionFailure) error {
	if len(failures) == 0 {
		return nil
	}
	return &provider.PartialCollectionError{
		Assets:   assets,
		Failures: failures,
	}
}

func asPartialCollectionError(err error) (*provider.PartialCollectionError, bool) {
	var partial *provider.PartialCollectionError
	if err == nil {
		return nil, false
	}
	if ok := errors.As(err, &partial); !ok || partial == nil {
		return nil, false
	}
	return partial, true
}

func resourceFailure(resourceType string, region string, err error) provider.CollectionFailure {
	category, message := collectionErrorDetails(err)
	return provider.CollectionFailure{
		ResourceType: resourceType,
		Region:       region,
		Category:     category,
		Message:      message,
	}
}

func collectionErrorDetails(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	return classifyCollectionError(err), sanitizeCollectionMessage(fmt.Sprint(err))
}

func classifyCollectionError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, ErrResourceAdapterNotImplemented) {
		return "unsupported"
	}

	message := strings.ToLower(err.Error())
	if category := classifyCollectionErrorCode(err.Error()); category != "" {
		return category
	}
	switch {
	case strings.Contains(message, "entitynotexist.user.loginprofile"),
		strings.Contains(message, "login profile does not exist"):
		return "expected_absent"
	case strings.Contains(message, "deadline exceeded"),
		strings.Contains(message, "timeout"),
		strings.Contains(message, "timed out"):
		return "timeout"
	case strings.Contains(message, "serviceunavailable"),
		strings.Contains(message, "temporary failure of the server"),
		strings.Contains(message, "temporary failure in name resolution"),
		strings.Contains(message, "statuscode: 503"),
		strings.Contains(message, "status code: 503"):
		return "transient"
	case strings.Contains(message, "throttl"),
		strings.Contains(message, "too many requests"),
		strings.Contains(message, "qps"),
		strings.Contains(message, "rate limit"),
		strings.Contains(message, "flow control"):
		return "throttling"
	case strings.Contains(message, "accessdenied"),
		strings.Contains(message, "forbidden"),
		strings.Contains(message, "nopermission"),
		strings.Contains(message, "unauthorized"),
		strings.Contains(message, "not authorized"),
		strings.Contains(message, "permission"):
		return "permission"
	case strings.Contains(message, "invalidaccesskeyid"),
		strings.Contains(message, "signaturedoesnotmatch"),
		strings.Contains(message, "invalid security token"):
		return "credential"
	case strings.Contains(message, "not open"),
		strings.Contains(message, "not enabled"),
		strings.Contains(message, "not activated"),
		strings.Contains(message, "servicenotenabled"),
		strings.Contains(message, "servicedisabled"),
		strings.Contains(message, "servicenotfound"),
		strings.Contains(message, "productnotfound"):
		return "product_not_enabled"
	case strings.Contains(message, "notsupportedendpoint"),
		strings.Contains(message, "unsupportedendpoint"),
		strings.Contains(message, "unsupportedoperation") && strings.Contains(message, "this action is not supported"),
		strings.Contains(message, "invalidregionid"),
		strings.Contains(message, "regionnotsupporterror"),
		strings.Contains(message, "profileregion.unsupported"),
		strings.Contains(message, "can not resolve endpoint"),
		strings.Contains(message, "aliyuncs.com") && strings.Contains(message, "no such host"),
		strings.Contains(message, "specified endpoint cant operate this region"):
		return "unsupported_region"
	case strings.Contains(message, "missingfunctionnames"),
		strings.Contains(message, "missingappidorappowner"),
		strings.Contains(message, "missingshowglobalview"),
		strings.Contains(message, "missingbackendbucketregionid"),
		strings.Contains(message, "missingpagenum"),
		strings.Contains(message, "missingpagesize"),
		strings.Contains(message, "missingnexttoken"),
		strings.Contains(message, "invalidaction.notfound"),
		strings.Contains(message, "invalidnexttoken"),
		strings.Contains(message, "badpagesize"),
		strings.Contains(message, "badrequest"),
		strings.Contains(message, "illegalparam.cenidorregionid"),
		strings.Contains(message, "invalidpagesize"),
		strings.Contains(message, "invalidparameter"),
		strings.Contains(message, "invalidsnattableid"):
		return "collector_request"
	case strings.Contains(message, "connection refused"),
		strings.Contains(message, "no such host"),
		strings.Contains(message, "dial tcp"),
		strings.Contains(message, "eof"),
		strings.Contains(message, "network"):
		return "network"
	default:
		return "unknown"
	}
}

func classifyCollectionErrorCode(message string) string {
	code := strings.ToLower(collectionErrorCode(message))
	lower := strings.ToLower(message)
	switch code {
	case "":
	case "serviceunavailable":
		return "transient"
	case "api.forbidden":
		return "permission"
	case "invalididentity.servicedisabled",
		"dcdnipaservicenotfound",
		"servicenotenabled",
		"servicedisabled",
		"servicenotfound",
		"productnotfound":
		return "product_not_enabled"
	case "notsupportedendpoint",
		"unsupportedendpoint",
		"invalidregionid",
		"regionnotsupporterror",
		"profileregion.unsupported":
		return "unsupported_region"
	case "unsupportedoperation":
		if strings.Contains(lower, "this action is not supported") {
			return "unsupported_region"
		}
	case "missingfunctionnames",
		"missingappidorappowner",
		"missingshowglobalview",
		"missingbackendbucketregionid",
		"missingpagenum",
		"missingpagesize",
		"missingnexttoken",
		"invalidaction.notfound",
		"invalidnexttoken",
		"badpagesize",
		"badrequest",
		"illegal_request",
		"illegalparam.cenidorregionid",
		"invalidpagesize",
		"invalidparameter",
		"invalidsnattableid":
		return "collector_request"
	}
	if strings.Contains(lower, "tenant id is empty") {
		return "collector_request"
	}
	return ""
}

var collectionErrorCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bErrorCode:\s*([A-Za-z0-9._-]+)`),
	regexp.MustCompile(`(?i)\bCode:\s*([A-Za-z0-9._-]+)`),
	regexp.MustCompile(`(?i)"Code"\s*:\s*"([^"]+)"`),
}

func collectionErrorCode(message string) string {
	for _, pattern := range collectionErrorCodePatterns {
		matches := pattern.FindStringSubmatch(message)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}
	return ""
}

func retryableCollectionError(err error) bool {
	return classifyCollectionError(err) == "transient"
}

func retryDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	return time.Duration(attempt) * 500 * time.Millisecond
}

var collectionMessageRedactions = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(AccessKeyId=)[^&\s"']+`),
	regexp.MustCompile(`(?i)(AccessKeySecret=)[^&\s"']+`),
	regexp.MustCompile(`(?i)(SecurityToken=)[^&\s"']+`),
	regexp.MustCompile(`(?i)(Signature=)[^&\s"']+`),
	regexp.MustCompile(`(?i)(SignatureNonce=)[^&\s"']+`),
	regexp.MustCompile(`(?i)("AccessKeyId"\s*:\s*")[^"]+`),
	regexp.MustCompile(`(?i)("AccessKeySecret"\s*:\s*")[^"]+`),
	regexp.MustCompile(`(?i)("SecurityToken"\s*:\s*")[^"]+`),
	regexp.MustCompile(`(?i)("Signature"\s*:\s*")[^"]+`),
	regexp.MustCompile(`(?i)\bLTAI[0-9A-Za-z]{12,}\b`),
}

func sanitizeCollectionMessage(value string) string {
	redacted := value
	for _, pattern := range collectionMessageRedactions {
		redacted = pattern.ReplaceAllString(redacted, `${1}<redacted>`)
	}
	return redacted
}
