package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/antgroup/CloudRec/lite/providers/alicloud"
	keyring "github.com/zalando/go-keyring"
)

func TestRunCredentialsStoreStatusDeleteWithSecretStdin(t *testing.T) {
	keyring.MockInit()

	var storeOut bytes.Buffer
	err := runCredentialsWithIO([]string{
		"store",
		"--provider", "alicloud",
		"--profile", "unit-profile",
		"--access-key-id", "unit-ak",
		"--region", "cn-hangzhou",
		"--secret-stdin",
	}, strings.NewReader("unit-sk\n"), &storeOut)
	if err != nil {
		t.Fatalf("credentials store returned error: %v\n%s", err, storeOut.String())
	}
	if strings.Contains(storeOut.String(), "unit-ak") || strings.Contains(storeOut.String(), "unit-sk") {
		t.Fatalf("credentials store leaked credential material:\n%s", storeOut.String())
	}

	status, err := alicloud.CredentialProfileStatus("unit-profile")
	if err != nil {
		t.Fatalf("credential profile status: %v", err)
	}
	if !status.AccessKeyIDPresent || !status.AccessKeySecretPresent || status.Region != "cn-hangzhou" {
		t.Fatalf("unexpected credential status: %+v", status)
	}

	var statusOut bytes.Buffer
	err = runCredentialsWithIO([]string{
		"status",
		"--provider", "alicloud",
		"--profile", "unit-profile",
		"--format", "json",
	}, strings.NewReader(""), &statusOut)
	if err != nil {
		t.Fatalf("credentials status returned error: %v\n%s", err, statusOut.String())
	}
	if strings.Contains(statusOut.String(), "unit-ak") || strings.Contains(statusOut.String(), "unit-sk") {
		t.Fatalf("credentials status leaked credential material:\n%s", statusOut.String())
	}
	var decoded alicloud.StoredCredentialStatus
	if err := json.Unmarshal(statusOut.Bytes(), &decoded); err != nil {
		t.Fatalf("decode status json: %v\n%s", err, statusOut.String())
	}
	if !decoded.AccessKeyIDPresent || !decoded.AccessKeySecretPresent {
		t.Fatalf("expected present credential status, got %+v", decoded)
	}

	var deleteOut bytes.Buffer
	err = runCredentialsWithIO([]string{
		"delete",
		"--provider", "alicloud",
		"--profile", "unit-profile",
	}, strings.NewReader(""), &deleteOut)
	if err != nil {
		t.Fatalf("credentials delete returned error: %v\n%s", err, deleteOut.String())
	}
	deleted, err := alicloud.CredentialProfileStatus("unit-profile")
	if err != nil {
		t.Fatalf("credential profile status after delete: %v", err)
	}
	if deleted.Found {
		t.Fatalf("expected deleted credential profile, got %+v", deleted)
	}
}

func TestRunCredentialsStoreRequiresSecretFromSafeInput(t *testing.T) {
	keyring.MockInit()

	var out bytes.Buffer
	err := runCredentialsWithIO([]string{
		"store",
		"--provider", "alicloud",
		"--profile", "unit-profile",
		"--access-key-id", "unit-ak",
	}, strings.NewReader(""), &out)
	if err == nil {
		t.Fatal("expected missing safe secret input error")
	}
	if !strings.Contains(err.Error(), "--secret-stdin") {
		t.Fatalf("expected secret input hint, got %q", err.Error())
	}
}
