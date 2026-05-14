package alicloud

import (
	"context"
	"errors"
	"testing"
	"time"

	ims "github.com/alibabacloud-go/ims-20190815/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
)

func TestAccountAdapterCollectsCompatibleAsset(t *testing.T) {
	client := &fakeAccountClient{
		summary: &ims.GetAccountSummaryResponse{
			Body: &ims.GetAccountSummaryResponseBody{
				SummaryMap: &ims.GetAccountSummaryResponseBodySummaryMap{},
			},
		},
		report: &ims.GetAccountSecurityPracticeReportResponse{
			Body: &ims.GetAccountSecurityPracticeReportResponseBody{
				AccountSecurityPracticeInfo: &ims.GetAccountSecurityPracticeReportResponseBodyAccountSecurityPracticeInfo{
					AccountSecurityPracticeUserInfo: &ims.GetAccountSecurityPracticeReportResponseBodyAccountSecurityPracticeInfoAccountSecurityPracticeUserInfo{
						BindMfa:           tea.Bool(false),
						RootWithAccessKey: tea.Int32(1),
						UnusedAkNum:       tea.Int32(1),
					},
				},
			},
		},
		passwordPolicy: &ims.GetPasswordPolicyResponse{
			Body: &ims.GetPasswordPolicyResponseBody{
				PasswordPolicy: &ims.GetPasswordPolicyResponseBodyPasswordPolicy{
					MinimumPasswordLength:      tea.Int32(8),
					RequireLowercaseCharacters: tea.Bool(false),
				},
			},
		},
		ssoSettings: &ims.GetUserSsoSettingsResponse{
			Body: &ims.GetUserSsoSettingsResponseBody{
				UserSsoSettings: &ims.GetUserSsoSettingsResponseBodyUserSsoSettings{
					SsoEnabled: tea.Bool(false),
				},
			},
		},
		securityPreference: &ims.GetSecurityPreferenceResponse{
			Body: &ims.GetSecurityPreferenceResponseBody{
				SecurityPreference: &ims.GetSecurityPreferenceResponseBodySecurityPreference{
					LoginProfilePreference: &ims.GetSecurityPreferenceResponseBodySecurityPreferenceLoginProfilePreference{
						LoginNetworkMasks:    tea.String(""),
						MFAOperationForLogin: tea.String("independent"),
					},
				},
			},
		},
	}
	adapter := NewAccountAdapter(WithAccountClientFactory(func(string, Credentials, time.Duration) (AccountClient, error) {
		return client, nil
	}))

	assets, err := adapter.Collect(context.Background(), AdapterRequest{
		Account: liteprovider.Account{
			AccountID: "123456789",
		},
		Credentials: Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"},
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("len(assets) = %d, want 1", len(assets))
	}
	asset := assets[0]
	if asset.Type != "Account" || asset.Region != "global" {
		t.Fatalf("asset = %#v, want global Account asset", asset)
	}

	report := mapValue(t, asset.Properties, "AccountSecurityPracticeReport")
	userInfo := mapValue(t, report, "AccountSecurityPracticeUserInfo")
	if stringFromAny(userInfo["RootWithAccessKey"]) != "1" {
		t.Fatalf("RootWithAccessKey = %#v, want 1", userInfo["RootWithAccessKey"])
	}
	passwordPolicy := mapValue(t, asset.Properties, "PasswordPolicy")
	if stringFromAny(passwordPolicy["MinimumPasswordLength"]) != "8" {
		t.Fatalf("MinimumPasswordLength = %#v, want 8", passwordPolicy["MinimumPasswordLength"])
	}
	sso := mapValue(t, asset.Properties, "UserSsoSettings")
	if sso["SsoEnabled"] != false {
		t.Fatalf("SsoEnabled = %#v, want false", sso["SsoEnabled"])
	}
	preference := mapValue(t, asset.Properties, "SecurityPreference")
	loginPreference := mapValue(t, preference, "LoginProfilePreference")
	if loginPreference["MFAOperationForLogin"] != "independent" {
		t.Fatalf("MFAOperationForLogin = %#v, want independent", loginPreference["MFAOperationForLogin"])
	}
}

func TestDefaultCollectorRegistersAccountNativeAdapter(t *testing.T) {
	collector, ok := NewDefaultCollector().(*HybridCollector)
	if !ok {
		t.Fatalf("NewDefaultCollector returned %T, want *HybridCollector", NewDefaultCollector())
	}
	if !collector.native.HasAdapter("Account") {
		t.Fatal("default native registry missing Account adapter")
	}
}

type fakeAccountClient struct {
	summary            *ims.GetAccountSummaryResponse
	report             *ims.GetAccountSecurityPracticeReportResponse
	passwordPolicy     *ims.GetPasswordPolicyResponse
	ssoSettings        *ims.GetUserSsoSettingsResponse
	securityPreference *ims.GetSecurityPreferenceResponse
	err                error
}

func (client *fakeAccountClient) GetAccountSummary() (*ims.GetAccountSummaryResponse, error) {
	if client.err != nil {
		return nil, client.err
	}
	return client.summary, nil
}

func (client *fakeAccountClient) GetAccountSecurityPracticeReport() (*ims.GetAccountSecurityPracticeReportResponse, error) {
	if client.err != nil {
		return nil, client.err
	}
	return client.report, nil
}

func (client *fakeAccountClient) GetPasswordPolicy() (*ims.GetPasswordPolicyResponse, error) {
	if client.err != nil {
		return nil, client.err
	}
	return client.passwordPolicy, nil
}

func (client *fakeAccountClient) GetUserSsoSettings() (*ims.GetUserSsoSettingsResponse, error) {
	if client.err != nil {
		return nil, client.err
	}
	return client.ssoSettings, nil
}

func (client *fakeAccountClient) GetSecurityPreference() (*ims.GetSecurityPreferenceResponse, error) {
	if client.err != nil {
		return nil, client.err
	}
	return client.securityPreference, nil
}

func TestAccountAdapterReturnsClientFactoryError(t *testing.T) {
	adapter := NewAccountAdapter(WithAccountClientFactory(func(string, Credentials, time.Duration) (AccountClient, error) {
		return nil, errors.New("factory failed")
	}))

	_, err := adapter.Collect(context.Background(), AdapterRequest{
		Account:     liteprovider.Account{AccountID: "123456789"},
		Credentials: Credentials{AccessKeyID: "ak", AccessKeySecret: "sk"},
		Timeout:     time.Second,
	})
	if err == nil || err.Error() != "factory failed" {
		t.Fatalf("error = %v, want factory failed", err)
	}
}
