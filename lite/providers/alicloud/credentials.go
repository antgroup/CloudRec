package alicloud

import (
	"fmt"
	"os"
	"strings"

	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
)

const (
	EnvAccessKeyID     = "ALIBABA_CLOUD_ACCESS_KEY_ID"
	EnvAccessKeySecret = "ALIBABA_CLOUD_ACCESS_KEY_SECRET"
	EnvSecurityToken   = "ALIBABA_CLOUD_SECURITY_TOKEN"
	EnvRegion          = "ALIBABA_CLOUD_REGION"
	EnvRegionID        = "ALIBABA_CLOUD_REGION_ID"

	ConfigCredentialSource  = "credential_source"
	ConfigCredentialProfile = "credential_profile"

	CredentialSourceAuto    = "auto"
	CredentialSourceKeyring = "keyring"
	CredentialSourceFile    = "file"
	CredentialSourceEnv     = "env"

	DefaultCredentialProfile = "default"
)

// Credentials contains the minimum credential set required by Alibaba Cloud SDKs.
type Credentials struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
	Region          string
}

// ResolveCredentials reads credentials from explicit account credentials first,
// then from the OS credential store, then from the local encrypted file
// fallback, then from standard Alibaba Cloud environment variables. The
// credential source can be restricted with account.Config[ConfigCredentialSource].
func ResolveCredentials(account liteprovider.Account) (Credentials, error) {
	source := CredentialSource(account)
	if !validCredentialSource(source) {
		return Credentials{}, fmt.Errorf("unsupported credential source %q; use auto, keyring, or env", source)
	}

	if credentials := accountCredentialValues(account); credentials.hasRequiredPair() {
		return credentials.withRegionFallback(accountRegion(account)), nil
	}

	profile := CredentialProfile(account)
	if source == CredentialSourceAuto || source == CredentialSourceKeyring {
		credentials, err := LoadKeyringCredentialProfile(profile)
		if err == nil && credentials.hasRequiredPair() {
			return credentials.withRegionFallback(accountRegion(account)), nil
		}
		if source == CredentialSourceKeyring {
			if err != nil {
				return Credentials{}, fmt.Errorf("system credential profile %q is unavailable: %w; run cloudrec-lite credentials store --provider alicloud --profile %s", profile, err, profile)
			}
			return Credentials{}, fmt.Errorf("system credential profile %q is missing access key id or secret; run cloudrec-lite credentials store --provider alicloud --profile %s", profile, profile)
		}
	}

	if source == CredentialSourceAuto || source == CredentialSourceFile {
		credentials, err := LoadFileCredentialProfile(profile)
		if err == nil && credentials.hasRequiredPair() {
			return credentials.withRegionFallback(accountRegion(account)), nil
		}
		if source == CredentialSourceFile {
			if err != nil {
				return Credentials{}, fmt.Errorf("local credential file profile %q is unavailable: %w; run cloudrec-lite credentials store --provider alicloud --profile %s", profile, err, profile)
			}
			return Credentials{}, fmt.Errorf("local credential file profile %q is missing access key id or secret; run cloudrec-lite credentials store --provider alicloud --profile %s", profile, profile)
		}
	}

	if source == CredentialSourceAuto || source == CredentialSourceEnv {
		if credentials := envCredentialValues(account); credentials.hasRequiredPair() {
			return credentials, nil
		}
		if source == CredentialSourceEnv {
			return Credentials{}, missingEnvCredentialError()
		}
	}

	return Credentials{}, fmt.Errorf("%w; or run cloudrec-lite credentials store --provider alicloud --profile %s", missingEnvCredentialError(), profile)
}

func CredentialSource(account liteprovider.Account) string {
	return NormalizeCredentialSource(stringFromStringMap(account.Config, ConfigCredentialSource, "credentials_source", "credentialSource"))
}

func NormalizeCredentialSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "":
		return CredentialSourceAuto
	case "system", "keychain", "key-ring", "credential-store", "credential_store":
		return CredentialSourceKeyring
	case "encrypted-file", "local-file", "local_file", "file", "filesystem":
		return CredentialSourceFile
	case "environment", "environ":
		return CredentialSourceEnv
	default:
		return strings.ToLower(strings.TrimSpace(source))
	}
}

func CredentialProfile(account liteprovider.Account) string {
	return firstNonEmpty(
		stringFromStringMap(account.Config, ConfigCredentialProfile, "credentials_profile", "credentialProfile", "profile"),
		account.AccountID,
		DefaultCredentialProfile,
	)
}

func validCredentialSource(source string) bool {
	switch source {
	case CredentialSourceAuto, CredentialSourceKeyring, CredentialSourceFile, CredentialSourceEnv:
		return true
	default:
		return false
	}
}

func credentialValues(account liteprovider.Account) Credentials {
	credentials := accountCredentialValues(account)
	if credentials.hasRequiredPair() {
		return credentials
	}
	return envCredentialValues(account)
}

func accountCredentialValues(account liteprovider.Account) Credentials {
	return Credentials{
		AccessKeyID: stringFromStringMap(account.Credentials,
			"access_key_id",
			"accessKeyId",
			"AccessKeyId",
			"AccessKeyID",
			"ak",
			EnvAccessKeyID,
		),
		AccessKeySecret: stringFromStringMap(account.Credentials,
			"access_key_secret",
			"accessKeySecret",
			"AccessKeySecret",
			"sk",
			EnvAccessKeySecret,
		),
		SecurityToken: stringFromStringMap(account.Credentials,
			"security_token",
			"securityToken",
			"SecurityToken",
			"token",
			EnvSecurityToken,
		),
		Region: firstNonEmpty(
			accountRegion(account),
			stringFromStringMap(account.Credentials, "region", "region_id", "default_region", EnvRegion, EnvRegionID),
		),
	}
}

func envCredentialValues(account liteprovider.Account) Credentials {
	return Credentials{
		AccessKeyID:     os.Getenv(EnvAccessKeyID),
		AccessKeySecret: os.Getenv(EnvAccessKeySecret),
		SecurityToken:   os.Getenv(EnvSecurityToken),
		Region: firstNonEmpty(
			accountRegion(account),
			os.Getenv(EnvRegion),
			os.Getenv(EnvRegionID),
		),
	}
}

func accountRegion(account liteprovider.Account) string {
	return firstNonEmpty(
		account.DefaultRegion,
		stringFromStringMap(account.Config, "region", "region_id", "default_region", EnvRegion, EnvRegionID),
	)
}

func missingEnvCredentialError() error {
	return fmt.Errorf("missing %s and %s", EnvAccessKeyID, EnvAccessKeySecret)
}

func (credentials Credentials) hasRequiredPair() bool {
	return strings.TrimSpace(credentials.AccessKeyID) != "" && strings.TrimSpace(credentials.AccessKeySecret) != ""
}

func (credentials Credentials) withRegionFallback(region string) Credentials {
	credentials.Region = firstNonEmpty(region, credentials.Region)
	return credentials
}

func stringFromStringMap(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
