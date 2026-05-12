package provider

import (
	"context"
	"fmt"
	"strings"
)

// Provider collects cloud assets and normalizes them for CloudRec Lite.
type Provider interface {
	Name() string
	ValidateAccount(ctx context.Context, account Account) error
	CollectAssets(ctx context.Context, account Account) ([]Asset, error)
	Capabilities() Capabilities
}

// Account describes the cloud account or subscription that should be scanned.
type Account struct {
	Provider      string
	AccountID     string
	DisplayName   string
	DefaultRegion string
	Credentials   map[string]string
	Config        map[string]string
}

// Capabilities advertises what a provider implementation can do.
type Capabilities struct {
	AssetTypes                    []string
	Regions                       []string
	SupportsAccountValidation     bool
	SupportsIncrementalCollection bool
	SupportsResourceRelationships bool
	MaxConcurrency                int
}

// Asset is the normalized resource shape passed from providers to core, rules,
// and storage.
type Asset struct {
	ID            string
	Provider      string
	AccountID     string
	Type          string
	Name          string
	Region        string
	Tags          map[string]string
	Properties    map[string]any
	Relationships []Relationship
}

// Relationship captures a normalized edge to another cloud resource.
type Relationship struct {
	Type       string
	TargetID   string
	Properties map[string]any
}

type CollectionFailure struct {
	ResourceType string `json:"resource_type,omitempty"`
	Region       string `json:"region,omitempty"`
	Category     string `json:"category,omitempty"`
	Message      string `json:"message"`
}

type PartialCollectionError struct {
	Assets   []Asset
	Failures []CollectionFailure
}

func (err *PartialCollectionError) Error() string {
	if err == nil {
		return ""
	}
	if len(err.Failures) == 0 {
		return "partial collection failed"
	}
	parts := make([]string, 0, len(err.Failures))
	for _, failure := range err.Failures {
		label := strings.TrimSpace(failure.ResourceType)
		if failure.Region != "" {
			label = fmt.Sprintf("%s/%s", label, failure.Region)
		}
		if label == "" {
			label = "resource"
		}
		parts = append(parts, fmt.Sprintf("%s: %s", label, failure.Message))
	}
	return "partial collection failed: " + strings.Join(parts, "; ")
}
