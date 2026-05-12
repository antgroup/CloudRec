package alicloud

import (
	"context"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ims "github.com/alibabacloud-go/ims-20190815/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/antgroup/CloudRec/lite/internal/provider"
	coreschema "github.com/core-sdk/schema"
)

type AccountClient interface {
	GetAccountSummary() (*ims.GetAccountSummaryResponse, error)
	GetAccountSecurityPracticeReport() (*ims.GetAccountSecurityPracticeReportResponse, error)
	GetPasswordPolicy() (*ims.GetPasswordPolicyResponse, error)
	GetUserSsoSettings() (*ims.GetUserSsoSettingsResponse, error)
	GetSecurityPreference() (*ims.GetSecurityPreferenceResponse, error)
}

type AccountClientFactory func(region string, credentials Credentials, timeout time.Duration) (AccountClient, error)

type AccountAdapter struct {
	clientFactory AccountClientFactory
}

type AccountAdapterOption func(*AccountAdapter)

func NewAccountAdapter(options ...AccountAdapterOption) *AccountAdapter {
	adapter := &AccountAdapter{
		clientFactory: newAccountClient,
	}
	for _, option := range options {
		option(adapter)
	}
	return adapter
}

func WithAccountClientFactory(factory AccountClientFactory) AccountAdapterOption {
	return func(adapter *AccountAdapter) {
		if factory != nil {
			adapter.clientFactory = factory
		}
	}
}

func (a *AccountAdapter) Spec() ResourceSpec {
	for _, spec := range AllResourceSpecs() {
		if normalizeResourceType(spec.Type) == "account" {
			return spec
		}
	}
	return ResourceSpec{Type: "Account", Group: "IDENTITY", Dimension: DimensionGlobal}
}

func (a *AccountAdapter) Collect(ctx context.Context, request AdapterRequest) ([]provider.Asset, error) {
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	collectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := a.clientFactory(firstNonEmpty(request.Credentials.Region, "cn-hangzhou"), request.Credentials, timeout)
	if err != nil {
		return nil, err
	}

	detail, err := collectAccountDetail(collectCtx, client)
	if err != nil {
		return nil, err
	}

	asset, err := assetFromLegacyData(request.Account, accountLegacyResource(), "global", detail)
	if err != nil {
		return nil, err
	}
	return []provider.Asset{asset}, nil
}

func newAccountClient(region string, credentials Credentials, timeout time.Duration) (AccountClient, error) {
	config := &openapi.Config{
		AccessKeyId:     tea.String(credentials.AccessKeyID),
		AccessKeySecret: tea.String(credentials.AccessKeySecret),
		SecurityToken:   tea.String(credentials.SecurityToken),
		RegionId:        tea.String(region),
		Endpoint:        tea.String("ims.aliyuncs.com"),
	}
	timeoutMS := int(timeout / time.Millisecond)
	if timeoutMS <= 0 {
		timeoutMS = 30000
	}
	config.SetConnectTimeout(timeoutMS)
	config.SetReadTimeout(timeoutMS)
	return ims.NewClient(config)
}

type accountDetail struct {
	AccountSummary                *ims.GetAccountSummaryResponseBodySummaryMap
	AccountSecurityPracticeReport *ims.GetAccountSecurityPracticeReportResponseBodyAccountSecurityPracticeInfo
	PasswordPolicy                *ims.GetPasswordPolicyResponseBodyPasswordPolicy
	UserSsoSettings               *ims.GetUserSsoSettingsResponseBodyUserSsoSettings
	SecurityPreference            *ims.GetSecurityPreferenceResponseBodySecurityPreference
}

func collectAccountDetail(ctx context.Context, client AccountClient) (accountDetail, error) {
	if err := ctx.Err(); err != nil {
		return accountDetail{}, err
	}
	summary, err := client.GetAccountSummary()
	if err != nil {
		return accountDetail{}, err
	}
	if err := ctx.Err(); err != nil {
		return accountDetail{}, err
	}
	report, err := client.GetAccountSecurityPracticeReport()
	if err != nil {
		return accountDetail{}, err
	}
	if err := ctx.Err(); err != nil {
		return accountDetail{}, err
	}
	passwordPolicy, err := client.GetPasswordPolicy()
	if err != nil {
		return accountDetail{}, err
	}
	if err := ctx.Err(); err != nil {
		return accountDetail{}, err
	}
	ssoSettings, err := client.GetUserSsoSettings()
	if err != nil {
		return accountDetail{}, err
	}
	if err := ctx.Err(); err != nil {
		return accountDetail{}, err
	}
	securityPreference, err := client.GetSecurityPreference()
	if err != nil {
		return accountDetail{}, err
	}

	return accountDetail{
		AccountSummary:                accountSummaryBody(summary),
		AccountSecurityPracticeReport: accountSecurityPracticeReportBody(report),
		PasswordPolicy:                passwordPolicyBody(passwordPolicy),
		UserSsoSettings:               userSsoSettingsBody(ssoSettings),
		SecurityPreference:            securityPreferenceBody(securityPreference),
	}, nil
}

func accountSummaryBody(response *ims.GetAccountSummaryResponse) *ims.GetAccountSummaryResponseBodySummaryMap {
	if response == nil || response.Body == nil {
		return nil
	}
	return response.Body.SummaryMap
}

func accountSecurityPracticeReportBody(response *ims.GetAccountSecurityPracticeReportResponse) *ims.GetAccountSecurityPracticeReportResponseBodyAccountSecurityPracticeInfo {
	if response == nil || response.Body == nil {
		return nil
	}
	return response.Body.AccountSecurityPracticeInfo
}

func passwordPolicyBody(response *ims.GetPasswordPolicyResponse) *ims.GetPasswordPolicyResponseBodyPasswordPolicy {
	if response == nil || response.Body == nil {
		return nil
	}
	return response.Body.PasswordPolicy
}

func userSsoSettingsBody(response *ims.GetUserSsoSettingsResponse) *ims.GetUserSsoSettingsResponseBodyUserSsoSettings {
	if response == nil || response.Body == nil {
		return nil
	}
	return response.Body.UserSsoSettings
}

func securityPreferenceBody(response *ims.GetSecurityPreferenceResponse) *ims.GetSecurityPreferenceResponseBodySecurityPreference {
	if response == nil || response.Body == nil {
		return nil
	}
	return response.Body.SecurityPreference
}

func accountLegacyResource() coreschema.Resource {
	return coreschema.Resource{
		ResourceType: "Account",
		Dimension:    coreschema.Global,
	}
}
