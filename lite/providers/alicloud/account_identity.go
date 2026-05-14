package alicloud

import (
	"context"
	"strings"
	"time"
	"unicode"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
)

const cloudAccountIDConfigKey = "cloud_account_id"

func accountWithResolvedCloudAccountID(ctx context.Context, account liteprovider.Account, credentials Credentials) liteprovider.Account {
	if existing := cloudAccountIDFromConfig(account.Config); existing != "" {
		return account
	}

	accountID := strings.TrimSpace(account.AccountID)
	if isNumericCloudAccountID(accountID) {
		next := account
		next.Config = cloneStringConfig(account.Config)
		next.Config[cloudAccountIDConfigKey] = accountID
		return next
	}

	resolved, err := resolveCallerAccountID(ctx, account, credentials)
	if err != nil || resolved == "" {
		return account
	}

	next := account
	next.Config = cloneStringConfig(account.Config)
	next.Config[cloudAccountIDConfigKey] = resolved
	return next
}

func cloudAccountIDFromConfig(config map[string]string) string {
	return firstNonEmpty(
		stringFromStringMap(config, cloudAccountIDConfigKey, "cloudAccountId", "alicloud_account_id", "aliyun_account_id"),
	)
}

func resolveCallerAccountID(ctx context.Context, account liteprovider.Account, credentials Credentials) (string, error) {
	region := firstNonEmpty(credentials.Region, account.DefaultRegion, "cn-hangzhou")
	var (
		client *sts.Client
		err    error
	)
	if credentials.SecurityToken != "" {
		client, err = sts.NewClientWithStsToken(region, credentials.AccessKeyID, credentials.AccessKeySecret, credentials.SecurityToken)
	} else {
		client, err = sts.NewClientWithAccessKey(region, credentials.AccessKeyID, credentials.AccessKeySecret)
	}
	if err != nil {
		return "", err
	}
	if proxy := firstNonEmpty(account.Config["proxy"], account.Config["proxy_config"]); proxy != "" {
		client.SetHttpProxy(proxy)
		client.SetHttpsProxy(proxy)
	}

	request := sts.CreateGetCallerIdentityRequest()
	request.SetConnectTimeout(5 * time.Second)
	request.SetReadTimeout(5 * time.Second)

	type callerIdentityResult struct {
		accountID string
		err       error
	}
	resultCh := make(chan callerIdentityResult, 1)
	go func() {
		response, err := client.GetCallerIdentity(request)
		if err != nil {
			resultCh <- callerIdentityResult{err: err}
			return
		}
		resultCh <- callerIdentityResult{accountID: strings.TrimSpace(response.AccountId)}
	}()

	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	select {
	case <-lookupCtx.Done():
		return "", lookupCtx.Err()
	case result := <-resultCh:
		return result.accountID, result.err
	}
}

func isNumericCloudAccountID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 6 {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
