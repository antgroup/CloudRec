package alicloud

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	keyring "github.com/zalando/go-keyring"
)

const (
	credentialStoreService = "cloudrec-lite/alicloud"

	credentialBackendKeyring = "keyring"
	credentialBackendFile    = "local_encrypted_file"

	EnvCredentialDir = "CLOUDREC_LITE_CREDENTIAL_DIR"
)

type StoredCredentialStatus struct {
	Profile                string `json:"profile"`
	Found                  bool   `json:"found"`
	Backend                string `json:"backend,omitempty"`
	Path                   string `json:"path,omitempty"`
	SecurityNote           string `json:"security_note,omitempty"`
	AccessKeyIDPresent     bool   `json:"access_key_id_present"`
	AccessKeySecretPresent bool   `json:"access_key_secret_present"`
	SecurityTokenPresent   bool   `json:"security_token_present"`
	Region                 string `json:"region,omitempty"`
}

type storedCredentialRecord struct {
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	SecurityToken   string `json:"security_token,omitempty"`
	Region          string `json:"region,omitempty"`
}

type localCredentialFile struct {
	Version      int    `json:"version"`
	Backend      string `json:"backend"`
	Profile      string `json:"profile"`
	Algorithm    string `json:"algorithm"`
	Key          string `json:"key"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
	SecurityNote string `json:"security_note"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

func StoreCredentialProfile(profile string, credentials Credentials) error {
	_, err := StoreCredentialProfileAuto(profile, credentials)
	return err
}

func StoreCredentialProfileAuto(profile string, credentials Credentials) (StoredCredentialStatus, error) {
	profile = normalizeCredentialProfile(profile)
	if err := storeKeyringCredentialProfile(profile, credentials); err == nil {
		return CredentialProfileStatus(profile)
	} else if runtime.GOOS != "linux" {
		return StoredCredentialStatus{}, err
	}
	return StoreFileCredentialProfile(profile, credentials)
}

func storeKeyringCredentialProfile(profile string, credentials Credentials) error {
	credentials = trimCredentials(credentials)
	if !credentials.hasRequiredPair() {
		return fmt.Errorf("credential profile %q requires access key id and access key secret", profile)
	}
	payload, err := json.Marshal(storedCredentialRecord{
		AccessKeyID:     credentials.AccessKeyID,
		AccessKeySecret: credentials.AccessKeySecret,
		SecurityToken:   credentials.SecurityToken,
		Region:          credentials.Region,
	})
	if err != nil {
		return err
	}
	if err := keyring.Set(credentialStoreService, profile, string(payload)); err != nil {
		return fmt.Errorf("write system credential store profile %q: %w", profile, err)
	}
	return nil
}

func LoadCredentialProfile(profile string) (Credentials, error) {
	if credentials, err := LoadKeyringCredentialProfile(profile); err == nil {
		return credentials, nil
	}
	return LoadFileCredentialProfile(profile)
}

func LoadKeyringCredentialProfile(profile string) (Credentials, error) {
	profile = normalizeCredentialProfile(profile)
	payload, err := keyring.Get(credentialStoreService, profile)
	if err != nil {
		return Credentials{}, err
	}
	var record storedCredentialRecord
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return Credentials{}, fmt.Errorf("system credential profile %q is not valid CloudRec Lite credential JSON: %w", profile, err)
	}
	return trimCredentials(Credentials{
		AccessKeyID:     record.AccessKeyID,
		AccessKeySecret: record.AccessKeySecret,
		SecurityToken:   record.SecurityToken,
		Region:          record.Region,
	}), nil
}

func StoreFileCredentialProfile(profile string, credentials Credentials) (StoredCredentialStatus, error) {
	profile = normalizeCredentialProfile(profile)
	credentials = trimCredentials(credentials)
	if !credentials.hasRequiredPair() {
		return StoredCredentialStatus{}, fmt.Errorf("credential profile %q requires access key id and access key secret", profile)
	}
	content, err := json.Marshal(storedCredentialRecord{
		AccessKeyID:     credentials.AccessKeyID,
		AccessKeySecret: credentials.AccessKeySecret,
		SecurityToken:   credentials.SecurityToken,
		Region:          credentials.Region,
	})
	if err != nil {
		return StoredCredentialStatus{}, err
	}
	key, err := randomBytes(32)
	if err != nil {
		return StoredCredentialStatus{}, err
	}
	nonce, err := randomBytes(12)
	if err != nil {
		return StoredCredentialStatus{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return StoredCredentialStatus{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return StoredCredentialStatus{}, err
	}
	ciphertext := aead.Seal(nil, nonce, content, []byte(profile))
	now := time.Now().UTC().Format(time.RFC3339)
	path, err := credentialFilePath(profile)
	if err != nil {
		return StoredCredentialStatus{}, err
	}
	record := localCredentialFile{
		Version:      1,
		Backend:      credentialBackendFile,
		Profile:      profile,
		Algorithm:    "AES-256-GCM",
		Key:          base64.StdEncoding.EncodeToString(key),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
		SecurityNote: localCredentialSecurityNote(),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := writeLocalCredentialFile(path, record); err != nil {
		return StoredCredentialStatus{}, err
	}
	return CredentialProfileStatus(profile)
}

func LoadFileCredentialProfile(profile string) (Credentials, error) {
	profile = normalizeCredentialProfile(profile)
	path, err := credentialFilePath(profile)
	if err != nil {
		return Credentials{}, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Credentials{}, err
	}
	var record localCredentialFile
	if err := json.Unmarshal(content, &record); err != nil {
		return Credentials{}, fmt.Errorf("decode local credential file %q: %w", path, err)
	}
	if record.Version != 1 || record.Backend != credentialBackendFile {
		return Credentials{}, fmt.Errorf("local credential file %q has unsupported format", path)
	}
	key, err := base64.StdEncoding.DecodeString(record.Key)
	if err != nil {
		return Credentials{}, fmt.Errorf("decode local credential file key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(record.Nonce)
	if err != nil {
		return Credentials{}, fmt.Errorf("decode local credential file nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(record.Ciphertext)
	if err != nil {
		return Credentials{}, fmt.Errorf("decode local credential file ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Credentials{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Credentials{}, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(profile))
	if err != nil {
		return Credentials{}, fmt.Errorf("decrypt local credential file %q: %w", path, err)
	}
	var stored storedCredentialRecord
	if err := json.Unmarshal(plain, &stored); err != nil {
		return Credentials{}, fmt.Errorf("decode decrypted local credential file %q: %w", path, err)
	}
	return trimCredentials(Credentials{
		AccessKeyID:     stored.AccessKeyID,
		AccessKeySecret: stored.AccessKeySecret,
		SecurityToken:   stored.SecurityToken,
		Region:          stored.Region,
	}), nil
}

func DeleteCredentialProfile(profile string) error {
	profile = normalizeCredentialProfile(profile)
	keyringErr := keyring.Delete(credentialStoreService, profile)
	fileErr := DeleteFileCredentialProfile(profile)
	if fileErr != nil {
		return fileErr
	}
	if keyringErr == nil || errors.Is(keyringErr, keyring.ErrNotFound) {
		return nil
	}
	if runtime.GOOS == "linux" {
		return nil
	}
	return fmt.Errorf("delete system credential store profile %q: %w", profile, keyringErr)
}

func DeleteFileCredentialProfile(profile string) error {
	path, err := credentialFilePath(normalizeCredentialProfile(profile))
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("delete local credential file %q: %w", path, err)
}

func CredentialProfileStatus(profile string) (StoredCredentialStatus, error) {
	profile = normalizeCredentialProfile(profile)
	status := StoredCredentialStatus{Profile: profile}
	if credentials, err := LoadKeyringCredentialProfile(profile); err == nil {
		return credentialStatusFromCredentials(profile, credentials, credentialBackendKeyring, "", ""), nil
	} else if !errors.Is(err, keyring.ErrNotFound) && runtime.GOOS != "linux" {
		return status, err
	}
	credentials, err := LoadFileCredentialProfile(profile)
	if errors.Is(err, os.ErrNotExist) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	path, _ := credentialFilePath(profile)
	return credentialStatusFromCredentials(profile, credentials, credentialBackendFile, path, localCredentialSecurityNote()), nil
}

func credentialStatusFromCredentials(profile string, credentials Credentials, backend string, path string, note string) StoredCredentialStatus {
	status := StoredCredentialStatus{Profile: profile, Backend: backend, Path: path, SecurityNote: note}
	status.Found = true
	status.AccessKeyIDPresent = strings.TrimSpace(credentials.AccessKeyID) != ""
	status.AccessKeySecretPresent = strings.TrimSpace(credentials.AccessKeySecret) != ""
	status.SecurityTokenPresent = strings.TrimSpace(credentials.SecurityToken) != ""
	status.Region = strings.TrimSpace(credentials.Region)
	return status
}

func normalizeCredentialProfile(profile string) string {
	return firstNonEmpty(profile, DefaultCredentialProfile)
}

func trimCredentials(credentials Credentials) Credentials {
	return Credentials{
		AccessKeyID:     strings.TrimSpace(credentials.AccessKeyID),
		AccessKeySecret: strings.TrimSpace(credentials.AccessKeySecret),
		SecurityToken:   strings.TrimSpace(credentials.SecurityToken),
		Region:          strings.TrimSpace(credentials.Region),
	}
}

func credentialFilePath(profile string) (string, error) {
	dir, err := credentialFileDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(profile))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json"), nil
}

func credentialFileDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv(EnvCredentialDir)); dir != "" {
		return dir, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "cloudrec-lite", "credentials", "alicloud"), nil
}

func writeLocalCredentialFile(path string, record localCredentialFile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create local credential directory %q: %w", dir, err)
	}
	_ = os.Chmod(dir, 0o700)
	tmp, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create local credential file %q: %w", path, err)
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(record)
	closeErr := tmp.Close()
	if encodeErr != nil {
		_ = os.Remove(path + ".tmp")
		return fmt.Errorf("write local credential file %q: %w", path, encodeErr)
	}
	if closeErr != nil {
		_ = os.Remove(path + ".tmp")
		return fmt.Errorf("close local credential file %q: %w", path, closeErr)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		_ = os.Remove(path + ".tmp")
		return fmt.Errorf("replace local credential file %q: %w", path, err)
	}
	_ = os.Chmod(path, 0o600)
	return nil
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	return buf, nil
}

func localCredentialSecurityNote() string {
	return "local key is stored with encrypted credentials; protects against accidental plaintext exposure, not against same-user or root filesystem access"
}
