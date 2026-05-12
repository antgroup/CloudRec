package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFileSetsAllowedMissingValues(t *testing.T) {
	t.Setenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "")
	if err := os.Unsetenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"); err != nil {
		t.Fatalf("unset env: %v", err)
	}

	path := filepath.Join(t.TempDir(), ".env.local")
	writeMainTestFile(t, path, `
# local credentials
ALIBABA_CLOUD_ACCESS_KEY_SECRET=from-file
UNRELATED_SECRET=ignored
`)

	if err := loadEnvFile(path); err != nil {
		t.Fatalf("loadEnvFile returned error: %v", err)
	}
	if got := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"); got != "from-file" {
		t.Fatalf("secret = %q, want from-file", got)
	}
	if got := os.Getenv("UNRELATED_SECRET"); got != "" {
		t.Fatalf("unrelated secret = %q, want empty", got)
	}
}

func TestLoadEnvFileDoesNotOverrideExistingValues(t *testing.T) {
	t.Setenv("ALIBABA_CLOUD_REGION", "cn-shanghai")

	path := filepath.Join(t.TempDir(), ".env.local")
	writeMainTestFile(t, path, "ALIBABA_CLOUD_REGION=cn-hangzhou\n")

	if err := loadEnvFile(path); err != nil {
		t.Fatalf("loadEnvFile returned error: %v", err)
	}
	if got := os.Getenv("ALIBABA_CLOUD_REGION"); got != "cn-shanghai" {
		t.Fatalf("region = %q, want existing env value", got)
	}
}

func TestLoadEnvFileIgnoresMissingDefaultFile(t *testing.T) {
	if err := loadEnvFile(filepath.Join(t.TempDir(), ".env.local")); err != nil {
		t.Fatalf("loadEnvFile returned error: %v", err)
	}
}

func writeMainTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
