package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/internal/storage"
)

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	NewHandler(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	assertContentType(t, rec, "application/json")

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected ok health status, got %q", body["status"])
	}
}

func TestIndex(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	NewHandler(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	assertContentType(t, rec, "text/html")
	if !strings.Contains(rec.Body.String(), "CloudRec Lite") {
		t.Fatalf("expected index body to mention CloudRec Lite")
	}
}

func TestFindingsPassesFiltersAndReturnsJSON(t *testing.T) {
	store := &recordingStore{
		findings: []model.Finding{
			{
				ID:        "finding-1",
				AccountID: "account-1",
				RuleID:    "MOCK_PUBLIC_BUCKET",
				Severity:  model.SeverityHigh,
				Status:    model.FindingStatusOpen,
				Title:     "Public bucket",
			},
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings?account_id=account-1&status=open&severity=high&resource_type=storage.bucket&rule_id=MOCK_PUBLIC_BUCKET&limit=25", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	assertContentType(t, rec, "application/json")
	if store.calls != 1 {
		t.Fatalf("expected store to be called once, got %d", store.calls)
	}

	expectedFilter := storage.FindingFilter{
		AccountID:    "account-1",
		ResourceType: "storage.bucket",
		RuleID:       "MOCK_PUBLIC_BUCKET",
		Severity:     model.SeverityHigh,
		Status:       model.FindingStatusOpen,
		Limit:        25,
	}
	if store.filter != expectedFilter {
		t.Fatalf("expected filter %+v, got %+v", expectedFilter, store.filter)
	}

	var body findingsResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Count != 1 {
		t.Fatalf("expected response count 1, got %d", body.Count)
	}
	if len(body.Findings) != 1 || body.Findings[0].ID != "finding-1" {
		t.Fatalf("unexpected findings response: %+v", body.Findings)
	}
}

func TestFindingsHydrateRemediationFromRuleMetadata(t *testing.T) {
	dir := t.TempDir()
	writeServerRulePack(t, dir, "account", `{
		"id": "alicloud.account_202501081111_689362",
		"name": "主账号启用 AccessKey",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "account",
		"legacy": {
			"advice": "删除主账号下的 AK，改用 RAM User 或 Role。"
		}
	}`)
	store := &recordingStore{
		findings: []model.Finding{{
			ID:        "finding-1",
			AccountID: "account-1",
			RuleID:    "alicloud.account_202501081111_689362",
			Severity:  model.SeverityHigh,
			Status:    model.FindingStatusOpen,
			Title:     "主账号启用 AccessKey",
		}},
	}
	handler := NewHandler(store, WithRulesDir(dir), WithProvider("alicloud"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings?limit=10", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected findings status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var listBody findingsResponse
	if err := json.NewDecoder(rec.Body).Decode(&listBody); err != nil {
		t.Fatalf("decode findings response: %v", err)
	}
	if len(listBody.Findings) != 1 || !strings.Contains(listBody.Findings[0].Remediation, "删除主账号下的 AK") {
		t.Fatalf("list remediation was not hydrated: %+v", listBody.Findings)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/finding?id=finding-1", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected finding detail status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var detailBody findingDetailResponse
	if err := json.NewDecoder(rec.Body).Decode(&detailBody); err != nil {
		t.Fatalf("decode finding detail response: %v", err)
	}
	if !strings.Contains(detailBody.Finding.Remediation, "删除主账号下的 AK") {
		t.Fatalf("detail remediation was not hydrated: %+v", detailBody.Finding)
	}
}

func TestSummaryReturnsJSON(t *testing.T) {
	store := &recordingStore{
		summary: model.Summary{
			AccountID:         "account-1",
			AssetCount:        3,
			FindingCount:      2,
			OpenFindingCount:  1,
			RelationshipCount: 1,
			SeverityCounts:    map[string]int{model.SeverityHigh: 1},
			ScanDelta:         model.ScanDelta{AddedAssets: 1},
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/summary?account_id=account-1", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if store.summaryFilter.AccountID != "account-1" {
		t.Fatalf("expected account filter account-1, got %q", store.summaryFilter.AccountID)
	}
	var body model.Summary
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.AssetCount != 3 || body.ScanDelta.AddedAssets != 1 {
		t.Fatalf("unexpected summary body: %+v", body)
	}
}

func TestAssetsPassesFiltersAndReturnsJSON(t *testing.T) {
	store := &recordingStore{
		assets: []model.Asset{{
			ID:           "asset-1",
			AccountID:    "account-1",
			ResourceType: "storage.bucket",
			ResourceID:   "bucket-1",
		}},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/assets?account_id=account-1&resource_type=storage.bucket&limit=25", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	expectedFilter := storage.AssetFilter{
		AccountID:    "account-1",
		ResourceType: "storage.bucket",
		Limit:        25,
	}
	if store.assetFilter != expectedFilter {
		t.Fatalf("expected filter %+v, got %+v", expectedFilter, store.assetFilter)
	}
	var body assetsResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Count != 1 || body.Assets[0].ID != "asset-1" {
		t.Fatalf("unexpected assets response: %+v", body)
	}
}

func TestScanRunsAndRelationshipsReturnJSON(t *testing.T) {
	store := &recordingStore{
		scanRuns: []model.ScanRun{{
			ID:        "scan-1",
			AccountID: "account-1",
			Provider:  "mock",
			Status:    model.ScanRunStatusSucceeded,
		}},
		relationships: []model.AssetRelationship{{
			ID:                 "rel-1",
			AccountID:          "account-1",
			SourceResourceType: "compute.instance",
			RelationshipType:   "member_of",
			TargetResourceID:   "vpc-1",
		}},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/scan-runs?account_id=account-1&status=succeeded&limit=5", nil)
	NewHandler(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected scan runs status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if store.scanRunFilter.AccountID != "account-1" || store.scanRunFilter.Status != model.ScanRunStatusSucceeded || store.scanRunFilter.Limit != 5 {
		t.Fatalf("unexpected scan run filter: %+v", store.scanRunFilter)
	}
	var runsBody scanRunsResponse
	if err := json.NewDecoder(rec.Body).Decode(&runsBody); err != nil {
		t.Fatalf("decode scan runs response: %v", err)
	}
	if runsBody.Count != 1 || runsBody.ScanRuns[0].ID != "scan-1" {
		t.Fatalf("unexpected scan runs response: %+v", runsBody)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/relationships?account_id=account-1&resource_type=compute.instance&relationship_type=member_of&limit=5", nil)
	NewHandler(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected relationships status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if store.relationshipFilter.AccountID != "account-1" || store.relationshipFilter.ResourceType != "compute.instance" || store.relationshipFilter.RelationshipType != "member_of" || store.relationshipFilter.Limit != 5 {
		t.Fatalf("unexpected relationship filter: %+v", store.relationshipFilter)
	}
	var relationshipsBody relationshipsResponse
	if err := json.NewDecoder(rec.Body).Decode(&relationshipsBody); err != nil {
		t.Fatalf("decode relationships response: %v", err)
	}
	if relationshipsBody.Count != 1 || relationshipsBody.Relationships[0].ID != "rel-1" {
		t.Fatalf("unexpected relationships response: %+v", relationshipsBody)
	}
}

func TestScanQualitySummarizesFailuresAndCoverage(t *testing.T) {
	store := &recordingStore{
		scanRuns: []model.ScanRun{
			{
				ID:        "scan-1",
				AccountID: "account-1",
				Provider:  "alicloud",
				Status:    model.ScanRunStatusSucceeded,
				Summary: rawJSON(t, map[string]any{
					"assets":              8,
					"findings":            3,
					"rules":               88,
					"evaluated_rules":     20,
					"skipped_rules":       68,
					"collection_failures": 2,
					"collection_failure_items": []map[string]any{
						{"resource_type": "RAM User", "region": "global", "category": "timeout", "message": "deadline exceeded"},
						{"resource_type": "RDS", "region": "cn-hangzhou", "category": "permission", "message": "forbidden"},
					},
				}),
			},
			{
				ID:        "scan-2",
				AccountID: "account-1",
				Provider:  "alicloud",
				Status:    model.ScanRunStatusFailed,
				Summary:   json.RawMessage(`{"assets":0,"rules":88}`),
			},
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/scan-quality?account_id=account-1&provider=alicloud&limit=10", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if store.scanRunFilter.AccountID != "account-1" || store.scanRunFilter.Provider != "alicloud" || store.scanRunFilter.Limit != 10 {
		t.Fatalf("unexpected scan run filter: %+v", store.scanRunFilter)
	}
	var body scanQualityResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode scan quality response: %v", err)
	}
	if body.Summary.TotalRuns != 2 || body.Summary.SucceededRuns != 1 || body.Summary.FailedRuns != 1 {
		t.Fatalf("unexpected run counts: %+v", body.Summary)
	}
	if body.Summary.CollectionHealth != "failed" || body.Summary.CollectionFailures != 2 {
		t.Fatalf("unexpected collection health: %+v", body.Summary)
	}
	if body.Summary.FailureCategories["timeout"] != 1 || body.Summary.FailureCategories["permission"] != 1 {
		t.Fatalf("unexpected failure categories: %+v", body.Summary.FailureCategories)
	}
	if len(body.Summary.ResourceTypes) != 2 || body.Summary.ResourceTypes[0].Failures != 1 || body.Summary.ResourceTypes[0].Hint == "" {
		t.Fatalf("unexpected resource type drilldown: %+v", body.Summary.ResourceTypes)
	}
	if body.Summary.EvaluationCoverage < 0.22 || body.Summary.EvaluationCoverage > 0.23 {
		t.Fatalf("unexpected evaluation coverage: %f", body.Summary.EvaluationCoverage)
	}
	if len(body.Runs) != 2 || body.Runs[0].QualityStatus != "partial" || len(body.Runs[0].FailureItems) != 2 || len(body.Runs[0].ResourceTypes) != 2 {
		t.Fatalf("unexpected quality runs: %+v", body.Runs)
	}
}

func TestRiskPathsClassifiesDataAndCredentialExposure(t *testing.T) {
	store := &recordingStore{
		assets: []model.Asset{
			{
				ID:           "oss-asset",
				AccountID:    "account-1",
				Provider:     "alicloud",
				ResourceType: "OSS",
				ResourceID:   "bucket-public",
				Region:       "cn-hangzhou",
				Name:         "bucket-public",
				Properties: rawJSON(t, map[string]any{
					"attributes": map[string]any{
						"BucketInfo": map[string]any{
							"ACL":               "public-read",
							"BlockPublicAccess": false,
						},
					},
				}),
			},
			{
				ID:           "sls-asset",
				AccountID:    "account-1",
				Provider:     "alicloud",
				ResourceType: "SLS",
				ResourceID:   "log-project",
				Region:       "cn-hangzhou",
				Name:         "log-project",
				Properties: rawJSON(t, map[string]any{
					"attributes": map[string]any{
						"PolicyStatus": map[string]any{
							"body": `[{"Effect":"Allow","Principal":["*"],"Action":["log:GetLogStoreLogs"],"Resource":["*"]}]`,
						},
					},
				}),
			},
			{
				ID:           "rds-asset",
				AccountID:    "account-1",
				Provider:     "alicloud",
				ResourceType: "RDS",
				ResourceID:   "rm-public",
				Region:       "cn-hangzhou",
				Name:         "rm-public",
				Properties: rawJSON(t, map[string]any{
					"attributes": map[string]any{
						"DBInstanceNetType": "Internet",
						"SecurityIPList":    "0.0.0.0/0",
					},
				}),
			},
			{
				ID:           "ram-asset",
				AccountID:    "account-1",
				Provider:     "alicloud",
				ResourceType: "RAMUser",
				ResourceID:   "user-risky",
				Name:         "user-risky",
				Properties: rawJSON(t, map[string]any{
					"attributes": map[string]any{
						"ExistActiveAccessKey": true,
						"AccessKeys": []map[string]any{
							{"AccessKey": map[string]any{"AccessKeyId": "LTAI1234567890ABCD", "Status": "Active"}},
						},
						"Policies": []map[string]any{
							{
								"Policy": map[string]any{"PolicyName": "data-access"},
								"DefaultPolicyVersion": map[string]any{
									"PolicyDocument": `{"Statement":[{"Effect":"Allow","Action":["log:*","rds:*"],"Resource":"*"}]}`,
								},
							},
						},
					},
				}),
			},
			{
				ID:           "ram-restricted",
				AccountID:    "account-1",
				Provider:     "alicloud",
				ResourceType: "RAMUser",
				ResourceID:   "user-restricted",
				Name:         "user-restricted",
				Properties: rawJSON(t, map[string]any{
					"attributes": map[string]any{
						"ExistActiveAccessKey": true,
						"Policies": []map[string]any{
							{
								"Policy": map[string]any{"PolicyName": "restricted-log"},
								"DefaultPolicyVersion": map[string]any{
									"PolicyDocument": `{"Statement":[{"Effect":"Allow","Action":"log:*","Resource":"*","Condition":{"IpAddress":{"acs:SourceIp":["10.0.0.0/8"]}}}]}`,
								},
							},
						},
					},
				}),
			},
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/risk-paths?account_id=account-1&provider=alicloud&region=cn-hangzhou&limit=20", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	expectedFilter := storage.AssetFilter{
		AccountID: "account-1",
		Provider:  "alicloud",
		Limit:     maxListLimit,
	}
	if store.assetFilter != expectedFilter {
		t.Fatalf("expected asset filter %+v, got %+v", expectedFilter, store.assetFilter)
	}
	var body riskPathsResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode risk paths response: %v", err)
	}
	if body.Summary.AnonymousPublicDataAccess != 2 {
		t.Fatalf("expected 2 anonymous public data paths, got %+v", body.Summary)
	}
	if body.Summary.DirectNetworkExposure != 1 {
		t.Fatalf("expected 1 direct network exposure, got %+v", body.Summary)
	}
	if body.Summary.CredentialDataAccess != 1 {
		t.Fatalf("expected 1 credential data path, got %+v", body.Summary)
	}
	if body.Summary.CredentialControlPlaneExposure != 1 {
		t.Fatalf("expected 1 credential control-plane path, got %+v", body.Summary)
	}
	if body.Total != 5 || body.Count != 5 {
		t.Fatalf("unexpected risk path counts: %+v", body)
	}
	if body.GroupsTotal != 5 || len(body.Groups) != 5 {
		t.Fatalf("unexpected risk path groups: total=%d groups=%+v", body.GroupsTotal, body.Groups)
	}
	for _, path := range body.Paths {
		if path.Source != nil && path.Source.ResourceID == "user-restricted" {
			t.Fatalf("source-restricted RAM user should not create a path: %+v", path)
		}
		if path.Source != nil && path.Source.ResourceID == "user-risky" {
			if path.Evidence["source_acl_status"] != "unrestricted" || path.Evidence["policy_documents_collected"] != true {
				t.Fatalf("expected unrestricted collected source ACL evidence: %+v", path.Evidence)
			}
			keys := stringSliceFromAny(path.Evidence["active_access_keys"])
			if len(keys) != 1 || keys[0] != "****ABCD" {
				t.Fatalf("expected masked active access key evidence, got %+v", path.Evidence["active_access_keys"])
			}
		}
	}
}

func TestRiskPathsBuildsPublicTrafficPaths(t *testing.T) {
	assets := []model.Asset{
		{
			ID:           "lb-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "SLB",
			ResourceID:   "lb-1",
			Region:       "cn-hangzhou",
			Name:         "public-lb",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"LoadBalancer": map[string]any{
						"AddressType": "internet",
						"Address":     "8.8.8.8",
					},
					"Listeners": []map[string]any{
						{"Listener": map[string]any{"ListenerPort": "80", "ListenerProtocol": "tcp", "AclStatus": "off"}},
					},
					"BackendServers": []map[string]any{
						{"ServerId": "i-1", "ServerType": "ecs", "Port": "80", "Weight": "100"},
					},
				},
			}),
		},
		{
			ID:           "ecs-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "ECS",
			ResourceID:   "i-1",
			Region:       "cn-hangzhou",
			Name:         "web-1",
		},
		{
			ID:           "sg-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "Security Group",
			ResourceID:   "sg-1",
			Region:       "cn-hangzhou",
			Name:         "web-sg",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"Permissions": []map[string]any{
						{"Direction": "ingress", "Policy": "accept", "SourceCidrIp": "0.0.0.0/0", "IpProtocol": "TCP", "PortRange": "80/80"},
					},
				},
			}),
		},
	}
	relationships := []model.AssetRelationship{{
		ID:                 "rel-1",
		AccountID:          "account-1",
		Provider:           "alicloud",
		SourceResourceType: "ECS",
		SourceResourceID:   "i-1",
		RelationshipType:   "uses_security_group",
		TargetResourceID:   "sg-1",
	}}

	body := buildRiskPathResponse(assets, relationships, riskPathFilter{Limit: 10})

	if body.Summary.PublicTrafficExposure != 1 || body.TrafficTotal != 1 || body.TrafficCount != 1 || len(body.TrafficPaths) != 1 {
		t.Fatalf("expected one traffic path, got %+v", body)
	}
	path := body.TrafficPaths[0]
	if path.OpenPolicyCount != 1 || len(path.Backends) != 1 || len(path.Backends[0].SecurityGroups) != 1 {
		t.Fatalf("unexpected traffic path: %+v", path)
	}
	if path.Severity != model.SeverityCritical || !containsString(path.Signals, "wide_open_security_group") {
		t.Fatalf("expected critical wide-open traffic path, got %+v", path)
	}
}

func TestRiskPathsIncludesCloudFirewallInboundControls(t *testing.T) {
	assets := []model.Asset{
		{
			ID:           "lb-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "SLB",
			ResourceID:   "lb-1",
			Region:       "cn-hangzhou",
			Name:         "public-lb",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"LoadBalancer": map[string]any{
						"AddressType": "internet",
						"Address":     "8.8.8.8",
					},
					"Listeners": []map[string]any{
						{"Listener": map[string]any{"ListenerPort": "443", "ListenerProtocol": "TCP", "AclStatus": "on"}},
					},
					"BackendServers": []map[string]any{
						{"ServerId": "i-1", "ServerType": "ecs", "Port": "443"},
					},
				},
			}),
		},
		{ID: "ecs-1", AccountID: "account-1", Provider: "alicloud", ResourceType: "ECS", ResourceID: "i-1", Region: "cn-hangzhou", Name: "web-1"},
		{
			ID:           "sg-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "Security Group",
			ResourceID:   "sg-1",
			Region:       "cn-hangzhou",
			Name:         "web-sg",
			Properties: rawJSON(t, map[string]any{"attributes": map[string]any{"Permissions": []map[string]any{
				{"Direction": "ingress", "Policy": "accept", "SourceCidrIp": "10.0.0.0/8", "IpProtocol": "TCP", "PortRange": "443/443"},
			}}}),
		},
		{
			ID:           "cloudfw-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "Cloudfw",
			ResourceID:   "fw-policy-1",
			Region:       "global",
			Name:         "internet-fw-policy",
			Properties: rawJSON(t, map[string]any{"attributes": map[string]any{"Policy": map[string]any{
				"AclUuid":     "fw-policy-1",
				"Direction":   "in",
				"AclAction":   "accept",
				"Source":      "0.0.0.0/0",
				"Destination": "8.8.8.8",
				"Proto":       "TCP",
				"DestPort":    "443",
				"Order":       "1",
			}}}),
		},
	}
	relationships := []model.AssetRelationship{{
		ID:                 "rel-1",
		AccountID:          "account-1",
		Provider:           "alicloud",
		SourceResourceType: "ECS",
		SourceResourceID:   "i-1",
		RelationshipType:   "uses_security_group",
		TargetResourceID:   "sg-1",
	}}

	body := buildRiskPathResponse(assets, relationships, riskPathFilter{PathType: riskPathPublicTrafficExposure, OpenPolicy: "true", Port: "443", Limit: 10})

	if body.TrafficTotal != 1 || len(body.TrafficPaths) != 1 {
		t.Fatalf("expected one CloudFW-controlled traffic path, got %+v", body)
	}
	path := body.TrafficPaths[0]
	if path.CloudFWAllowCount != 1 || path.OpenPolicyCount != 1 || len(path.CloudFirewall) != 1 {
		t.Fatalf("expected CloudFW allow policy to contribute to open policy count, got %+v", path)
	}
	if !path.CloudFirewall[0].Open || path.CloudFirewall[0].Action != "accept" || !containsString(path.Signals, "cloudfw_inbound_allow") {
		t.Fatalf("unexpected CloudFW policy evidence: %+v", path)
	}
}

func TestRiskPathsFiltersTrafficPathsByPortOpenPolicyAndPagination(t *testing.T) {
	assets := []model.Asset{
		{
			ID:           "lb-80",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "SLB",
			ResourceID:   "lb-80",
			Region:       "cn-hangzhou",
			Name:         "open-http",
			Properties: rawJSON(t, map[string]any{"attributes": map[string]any{
				"LoadBalancer":   map[string]any{"AddressType": "internet", "Address": "8.8.8.8"},
				"Listeners":      []map[string]any{{"ListenerPort": "80", "ListenerProtocol": "tcp", "AclStatus": "off"}},
				"BackendServers": []map[string]any{{"ServerId": "i-80", "ServerType": "ecs", "Port": "80"}},
			}}),
		},
		{
			ID:           "lb-443",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "SLB",
			ResourceID:   "lb-443",
			Region:       "cn-hangzhou",
			Name:         "restricted-https",
			Properties: rawJSON(t, map[string]any{"attributes": map[string]any{
				"LoadBalancer":   map[string]any{"AddressType": "internet", "Address": "8.8.4.4"},
				"Listeners":      []map[string]any{{"ListenerPort": "443", "ListenerProtocol": "tcp", "AclStatus": "on"}},
				"BackendServers": []map[string]any{{"ServerId": "i-443", "ServerType": "ecs", "Port": "443"}},
			}}),
		},
		{ID: "ecs-80", AccountID: "account-1", Provider: "alicloud", ResourceType: "ECS", ResourceID: "i-80", Region: "cn-hangzhou"},
		{ID: "ecs-443", AccountID: "account-1", Provider: "alicloud", ResourceType: "ECS", ResourceID: "i-443", Region: "cn-hangzhou"},
		{
			ID:           "sg-80",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "Security Group",
			ResourceID:   "sg-80",
			Region:       "cn-hangzhou",
			Properties: rawJSON(t, map[string]any{"attributes": map[string]any{"Permissions": []map[string]any{
				{"Direction": "ingress", "Policy": "accept", "SourceCidrIp": "0.0.0.0/0", "IpProtocol": "TCP", "PortRange": "80/80"},
			}}}),
		},
		{
			ID:           "sg-443",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "Security Group",
			ResourceID:   "sg-443",
			Region:       "cn-hangzhou",
			Properties: rawJSON(t, map[string]any{"attributes": map[string]any{"Permissions": []map[string]any{
				{"Direction": "ingress", "Policy": "accept", "SourceCidrIp": "10.0.0.0/8", "IpProtocol": "TCP", "PortRange": "443/443"},
			}}}),
		},
	}
	relationships := []model.AssetRelationship{
		{ID: "rel-80", AccountID: "account-1", Provider: "alicloud", SourceResourceType: "ECS", SourceResourceID: "i-80", RelationshipType: "uses_security_group", TargetResourceID: "sg-80"},
		{ID: "rel-443", AccountID: "account-1", Provider: "alicloud", SourceResourceType: "ECS", SourceResourceID: "i-443", RelationshipType: "uses_security_group", TargetResourceID: "sg-443"},
	}

	body := buildRiskPathResponse(assets, relationships, riskPathFilter{
		PathType:   riskPathPublicTrafficExposure,
		Port:       "80",
		OpenPolicy: "true",
		Limit:      1,
		Offset:     0,
	})

	if body.TrafficTotal != 1 || body.TrafficCount != 1 || len(body.TrafficPaths) != 1 {
		t.Fatalf("expected one filtered traffic path, got %+v", body)
	}
	if body.TrafficPaths[0].Entry.ResourceID != "lb-80" || body.TrafficPaths[0].OpenPolicyCount != 1 {
		t.Fatalf("unexpected filtered traffic path: %+v", body.TrafficPaths[0])
	}

	page := buildRiskPathResponse(assets, relationships, riskPathFilter{
		PathType: riskPathPublicTrafficExposure,
		Limit:    1,
		Offset:   1,
	})
	if page.TrafficTotal != 2 || page.TrafficCount != 2 || len(page.TrafficPaths) != 1 {
		t.Fatalf("unexpected paginated traffic paths: %+v", page)
	}
}

func TestRiskPathsBuildsALBNLBTrafficVariants(t *testing.T) {
	assets := []model.Asset{
		{
			ID:           "alb-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "ALB",
			ResourceID:   "alb-1",
			Region:       "cn-hangzhou",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"LoadBalancerAttribute": map[string]any{"AddressType": "Internet", "DNSName": "alb.internet.example.com"},
					"ListenerAttribute":     map[string]any{"ListenerPort": 443, "ListenerProtocol": "HTTPS", "AclStatus": "on"},
					"ServerGroup": map[string]any{
						"Servers": []map[string]any{{"ServerId": "i-alb", "ServerType": "Ecs", "Port": 443}},
					},
				},
			}),
		},
		{
			ID:           "nlb-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "NLB",
			ResourceID:   "nlb-1",
			Region:       "cn-shanghai",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"LoadBalancer": map[string]any{"AddressType": "Internet", "Address": "8.8.4.4"},
					"Listeners":    []map[string]any{{"StartPort": 53, "Protocol": "UDP", "AclStatus": "off"}},
					"BackendServers": []map[string]any{
						{"ServerId": "i-nlb", "ServerType": "ecs", "BackendServerPort": 53},
					},
				},
			}),
		},
		{ID: "ecs-alb", AccountID: "account-1", Provider: "alicloud", ResourceType: "ECS", ResourceID: "i-alb", Region: "cn-hangzhou"},
		{ID: "ecs-nlb", AccountID: "account-1", Provider: "alicloud", ResourceType: "ECS", ResourceID: "i-nlb", Region: "cn-shanghai"},
		{
			ID:           "sg-alb",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "Security Group",
			ResourceID:   "sg-alb",
			Region:       "cn-hangzhou",
			Properties: rawJSON(t, map[string]any{"attributes": map[string]any{
				"Permissions": []map[string]any{{"Direction": "ingress", "Policy": "accept", "SourceCidrIp": "10.0.0.0/8", "IpProtocol": "TCP", "PortRange": "443/443"}},
			}}),
		},
		{
			ID:           "sg-nlb",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "Security Group",
			ResourceID:   "sg-nlb",
			Region:       "cn-shanghai",
			Properties: rawJSON(t, map[string]any{"attributes": map[string]any{
				"Permissions": []map[string]any{{"Direction": "ingress", "Policy": "accept", "SourceCidrIp": "10.0.0.0/8", "IpProtocol": "UDP", "PortRange": "53/53"}},
			}}),
		},
	}
	relationships := []model.AssetRelationship{
		{ID: "rel-alb", AccountID: "account-1", Provider: "alicloud", SourceResourceType: "ECS", SourceResourceID: "i-alb", RelationshipType: "uses_security_group", TargetResourceID: "sg-alb"},
		{ID: "rel-nlb", AccountID: "account-1", Provider: "alicloud", SourceResourceType: "ECS", SourceResourceID: "i-nlb", RelationshipType: "uses_security_group", TargetResourceID: "sg-nlb"},
	}

	body := buildRiskPathResponse(assets, relationships, riskPathFilter{Limit: 10})

	if body.Summary.PublicTrafficExposure != 2 || body.TrafficTotal != 2 || len(body.TrafficPaths) != 2 {
		t.Fatalf("expected two ALB/NLB traffic paths, got %+v", body)
	}
	for _, path := range body.TrafficPaths {
		if len(path.Listeners) == 0 || len(path.Backends) == 0 || len(path.Backends[0].SecurityGroups) == 0 {
			t.Fatalf("expected listener, backend, and security group on path: %+v", path)
		}
		if path.OpenPolicyCount != 0 || path.Severity != model.SeverityHigh {
			t.Fatalf("expected restricted ALB/NLB paths to remain high without wide-open SG, got %+v", path)
		}
	}
}

func TestRiskPathsMarksMissingRAMSourceACLDocuments(t *testing.T) {
	assets := []model.Asset{
		{
			ID:           "oss-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "OSS",
			ResourceID:   "bucket-1",
			Name:         "bucket-1",
		},
		{
			ID:           "ram-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "RAM User",
			ResourceID:   "ram-user-1",
			Name:         "ram-user-1",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"AccessKeys": []map[string]any{
						{"AccessKey": map[string]any{"AccessKeyId": "LTAI1234567890WXYZ", "Status": "Active"}},
					},
					"Policies": []map[string]any{
						{"Policy": map[string]any{"PolicyName": "AliyunOSSFullAccess"}},
					},
				},
			}),
		},
	}

	body := buildRiskPathResponse(assets, nil, riskPathFilter{Limit: 10})

	if body.Summary.CredentialDataAccess != 1 || len(body.Paths) != 1 {
		t.Fatalf("expected one credential data path, got %+v", body)
	}
	path := body.Paths[0]
	if path.Evidence["source_acl_status"] != "not_collected" || path.Evidence["policy_documents_collected"] != false {
		t.Fatalf("expected missing source ACL document evidence, got %+v", path.Evidence)
	}
	if !containsString(path.Signals, "source_acl_not_collected") {
		t.Fatalf("expected source_acl_not_collected signal, got %+v", path.Signals)
	}
}

func TestRiskPathsGroupsCredentialTargets(t *testing.T) {
	assets := []model.Asset{
		{
			ID:           "oss-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "OSS",
			ResourceID:   "bucket-1",
			Name:         "bucket-1",
		},
		{
			ID:           "oss-2",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "OSS",
			ResourceID:   "bucket-2",
			Name:         "bucket-2",
		},
		{
			ID:           "ram-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "RAMUser",
			ResourceID:   "ram-user-1",
			Name:         "ram-user-1",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"ExistActiveAccessKey": true,
					"Policies": []map[string]any{
						{
							"Policy": map[string]any{"PolicyName": "AdministratorAccess"},
							"DefaultPolicyVersion": map[string]any{
								"PolicyDocument": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
							},
						},
					},
				},
			}),
		},
	}

	body := buildRiskPathResponse(assets, nil, riskPathFilter{Limit: 10})

	if body.Summary.CredentialDataAccess != 2 {
		t.Fatalf("expected two credential data paths, got %+v", body.Summary)
	}
	var credentialGroup *riskPathGroup
	for i := range body.Groups {
		if body.Groups[i].PathType == riskPathCredentialDataAccess && body.Groups[i].Service == "OSS" {
			credentialGroup = &body.Groups[i]
			break
		}
	}
	if credentialGroup == nil {
		t.Fatalf("expected OSS credential group, got %+v", body.Groups)
	}
	if credentialGroup.TargetCount != 2 || len(credentialGroup.Targets) != 2 {
		t.Fatalf("unexpected credential group: %+v", credentialGroup)
	}
}

func TestRiskPathsMatchesScopedOSSResourcePattern(t *testing.T) {
	assets := []model.Asset{
		{
			ID:           "oss-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "OSS",
			ResourceID:   "bucket-1",
			Name:         "bucket-1",
		},
		{
			ID:           "oss-2",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "OSS",
			ResourceID:   "bucket-2",
			Name:         "bucket-2",
		},
		{
			ID:           "ram-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "RAM User",
			ResourceID:   "ram-user-1",
			Name:         "ram-user-1",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"AccessKeys": []map[string]any{
						{"AccessKey": map[string]any{"AccessKeyId": "LTAI1234567890ABCD", "Status": "Active"}},
					},
					"Policies": []map[string]any{
						{
							"Policy": map[string]any{"PolicyName": "bucket-1-only"},
							"DefaultPolicyVersion": map[string]any{
								"PolicyDocument": `{"Statement":[{"Effect":"Allow","Action":"oss:*","Resource":["acs:oss:*:*:bucket-1","acs:oss:*:*:bucket-1/*"]}]}`,
							},
						},
					},
				},
			}),
		},
	}

	body := buildRiskPathResponse(assets, nil, riskPathFilter{Limit: 10})

	if body.Summary.CredentialDataAccess != 1 || len(body.Paths) != 1 {
		t.Fatalf("expected one scoped OSS credential path, got %+v", body)
	}
	if body.Paths[0].Target.ResourceID != "bucket-1" {
		t.Fatalf("expected scoped policy to match only bucket-1, got %+v", body.Paths[0])
	}
}

func TestRiskPathsSourceGuardRestrictsOnlyMatchingTarget(t *testing.T) {
	assets := []model.Asset{
		{
			ID:           "oss-guarded",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "OSS",
			ResourceID:   "bucket-guarded",
			Name:         "bucket-guarded",
		},
		{
			ID:           "oss-open",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "OSS",
			ResourceID:   "bucket-open",
			Name:         "bucket-open",
		},
		{
			ID:           "ram-1",
			AccountID:    "account-1",
			Provider:     "alicloud",
			ResourceType: "RAM User",
			ResourceID:   "ram-user-1",
			Name:         "ram-user-1",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"AccessKeys": []map[string]any{
						{"AccessKey": map[string]any{"AccessKeyId": "LTAI1234567890ABCD", "Status": "Active"}},
					},
					"Policies": []map[string]any{
						{
							"Policy": map[string]any{"PolicyName": "allow-all-oss-with-scoped-guard"},
							"DefaultPolicyVersion": map[string]any{
								"PolicyDocument": `{"Statement":[{"Effect":"Allow","Action":"oss:*","Resource":"*"},{"Effect":"Deny","Action":"oss:*","Resource":"acs:oss:*:*:bucket-guarded/*","Condition":{"NotIpAddress":{"acs:SourceIp":["10.0.0.0/8"]}}}]}`,
							},
						},
					},
				},
			}),
		},
	}

	body := buildRiskPathResponse(assets, nil, riskPathFilter{Limit: 10})

	if body.Summary.CredentialDataAccess != 1 || len(body.Paths) != 1 {
		t.Fatalf("expected one unguarded OSS credential path, got %+v", body)
	}
	if body.Paths[0].Target.ResourceID != "bucket-open" {
		t.Fatalf("expected source guard to suppress only bucket-guarded, got %+v", body.Paths[0])
	}
	if body.Paths[0].Evidence["source_acl_status"] != "unrestricted" {
		t.Fatalf("expected remaining path to be unrestricted, got %+v", body.Paths[0].Evidence)
	}
}

func TestDashboardPassesFiltersAndReturnsJSON(t *testing.T) {
	store := &recordingStore{
		summary: model.Summary{AssetCount: 3, OpenFindingCount: 1},
		findings: []model.Finding{{
			ID:        "finding-1",
			AccountID: "account-1",
			RuleID:    "RULE",
			Severity:  model.SeverityHigh,
			Status:    model.FindingStatusOpen,
		}},
		scanRuns: []model.ScanRun{{
			ID:        "scan-1",
			AccountID: "account-1",
			Provider:  "mock",
			Status:    model.ScanRunStatusSucceeded,
		}},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard?account_id=account-1&provider=mock&resource_type=storage.bucket&rule_id=RULE&severity=high&status=open&scan_status=succeeded&limit=5", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if store.summaryFilter.AccountID != "account-1" {
		t.Fatalf("unexpected summary filter: %+v", store.summaryFilter)
	}
	expectedFindingFilter := storage.FindingFilter{
		AccountID:    "account-1",
		ResourceType: "storage.bucket",
		RuleID:       "RULE",
		Severity:     model.SeverityHigh,
		Status:       model.FindingStatusOpen,
		Limit:        5,
	}
	if store.filter != expectedFindingFilter {
		t.Fatalf("expected finding filter %+v, got %+v", expectedFindingFilter, store.filter)
	}
	if store.scanRunFilter.AccountID != "account-1" || store.scanRunFilter.Provider != "mock" || store.scanRunFilter.Status != model.ScanRunStatusSucceeded || store.scanRunFilter.Limit != 5 {
		t.Fatalf("unexpected scan run filter: %+v", store.scanRunFilter)
	}
	var body dashboardResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode dashboard response: %v", err)
	}
	if body.Summary.AssetCount != 3 || len(body.TopFindings) != 1 || len(body.RecentScanRuns) != 1 {
		t.Fatalf("unexpected dashboard response: %+v", body)
	}
}

func TestFacetsPassesFiltersAndReturnsCounts(t *testing.T) {
	store := &recordingStore{
		assets: []model.Asset{{
			AccountID:    "account-1",
			Provider:     "mock",
			ResourceType: "storage.bucket",
			Region:       "local",
		}},
		findings: []model.Finding{{
			AccountID: "account-1",
			RuleID:    "RULE",
			Severity:  model.SeverityHigh,
			Status:    model.FindingStatusOpen,
		}},
		scanRuns: []model.ScanRun{{
			AccountID: "account-1",
			Provider:  "mock",
			Status:    model.ScanRunStatusSucceeded,
		}},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/facets?account_id=account-1&provider=mock&resource_type=storage.bucket&rule_id=RULE&severity=high&status=open&scan_status=succeeded&limit=25", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	expectedAssetFilter := storage.AssetFilter{
		AccountID:    "account-1",
		Provider:     "mock",
		ResourceType: "storage.bucket",
		Limit:        25,
	}
	if store.assetFilter != expectedAssetFilter {
		t.Fatalf("expected asset filter %+v, got %+v", expectedAssetFilter, store.assetFilter)
	}
	expectedFindingFilter := storage.FindingFilter{
		AccountID:    "account-1",
		ResourceType: "storage.bucket",
		RuleID:       "RULE",
		Severity:     model.SeverityHigh,
		Status:       model.FindingStatusOpen,
		Limit:        25,
	}
	if store.filter != expectedFindingFilter {
		t.Fatalf("expected finding filter %+v, got %+v", expectedFindingFilter, store.filter)
	}
	if store.scanRunFilter.Provider != "mock" || store.scanRunFilter.Status != model.ScanRunStatusSucceeded {
		t.Fatalf("unexpected scan run filter: %+v", store.scanRunFilter)
	}
	var body facetsResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode facets response: %v", err)
	}
	if len(body.Providers) != 1 || body.Providers[0].Value != "mock" || body.Providers[0].Count != 2 {
		t.Fatalf("unexpected provider facets: %+v", body.Providers)
	}
	if len(body.ResourceTypes) != 1 || body.ResourceTypes[0].Value != "storage.bucket" {
		t.Fatalf("unexpected resource type facets: %+v", body.ResourceTypes)
	}
	if len(body.Rules) != 1 || body.Rules[0].Value != "RULE" {
		t.Fatalf("unexpected rule facets: %+v", body.Rules)
	}
}

func TestFindingDetailRequiresIDAndReturnsFinding(t *testing.T) {
	store := &recordingStore{
		findings: []model.Finding{{
			ID:     "finding-1",
			RuleID: "RULE",
		}},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/finding", nil)
	NewHandler(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected missing id status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	assertJSONError(t, rec, "id is required")

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/finding?id=finding-1", nil)
	NewHandler(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if store.findingID != "finding-1" {
		t.Fatalf("expected finding id lookup finding-1, got %q", store.findingID)
	}
	var body findingDetailResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode finding detail response: %v", err)
	}
	if body.Finding.ID != "finding-1" {
		t.Fatalf("unexpected finding detail: %+v", body)
	}
}

func TestFindingDetailNotFound(t *testing.T) {
	store := &recordingStore{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/finding?id=missing", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
	assertJSONError(t, rec, "finding not found")
}

func TestAssetDetailPassesFiltersAndReturnsContext(t *testing.T) {
	store := &recordingStore{
		assets: []model.Asset{{
			ID:           "asset-1",
			AccountID:    "account-1",
			Provider:     "mock",
			ResourceType: "OSS",
			ResourceID:   "bucket-1",
			Properties: rawJSON(t, map[string]any{
				"attributes": map[string]any{
					"BucketInfo": map[string]any{
						"ACL":               "public-read",
						"BlockPublicAccess": false,
					},
				},
			}),
		}},
		findings: []model.Finding{{
			ID:      "finding-1",
			AssetID: "asset-1",
		}},
		relationships: []model.AssetRelationship{{
			ID:                 "rel-1",
			AccountID:          "account-1",
			SourceAssetID:      "asset-1",
			SourceResourceType: "storage.bucket",
			SourceResourceID:   "bucket-1",
			RelationshipType:   "contains",
			TargetResourceID:   "object-1",
		}},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/asset?account_id=account-1&provider=mock&resource_type=OSS&resource_id=bucket-1&limit=5", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	expectedAssetFilter := storage.AssetFilter{
		AccountID:    "account-1",
		Provider:     "mock",
		ResourceType: "OSS",
		ResourceID:   "bucket-1",
		Limit:        5,
	}
	if store.assetFilter != expectedAssetFilter {
		t.Fatalf("expected asset filter %+v, got %+v", expectedAssetFilter, store.assetFilter)
	}
	expectedFindingFilter := storage.FindingFilter{
		AccountID: "account-1",
		AssetID:   "asset-1",
		Limit:     5,
	}
	if store.filter != expectedFindingFilter {
		t.Fatalf("expected finding filter %+v, got %+v", expectedFindingFilter, store.filter)
	}
	var body assetDetailResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode asset detail response: %v", err)
	}
	if body.Asset.ID != "asset-1" || len(body.Findings) != 1 || len(body.Relationships) != 1 {
		t.Fatalf("unexpected asset detail response: %+v", body)
	}
	if body.ProductSummary["product"] != "OSS" || body.ProductSummary["effective_public"] != true {
		t.Fatalf("expected OSS product summary with effective public exposure, got %+v", body.ProductSummary)
	}
}

func TestAssetDetailRequiresIdentifier(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/asset", nil)

	NewHandler(&recordingStore{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	assertJSONError(t, rec, "id or resource_id is required")
}

func TestGraphPassesFiltersAndValidatesDepth(t *testing.T) {
	store := &recordingStore{
		relationships: []model.AssetRelationship{{
			ID:                 "rel-1",
			AccountID:          "account-1",
			Provider:           "mock",
			SourceResourceType: "compute.instance",
			SourceResourceID:   "instance-1",
			RelationshipType:   "member_of",
			TargetResourceID:   "sg-1",
		}},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/graph?depth=nope", nil)
	NewHandler(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid depth status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	assertJSONError(t, rec, "depth must be a positive integer")

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/graph?account_id=account-1&resource_type=compute.instance&source_resource_id=instance-1&target_resource_id=sg-1&relationship_type=member_of&depth=2&limit=5", nil)
	NewHandler(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	expectedFilter := storage.RelationshipFilter{
		AccountID:        "account-1",
		SourceResourceID: "instance-1",
		TargetResourceID: "sg-1",
		ResourceType:     "compute.instance",
		RelationshipType: "member_of",
		Limit:            5,
	}
	if store.relationshipFilter != expectedFilter {
		t.Fatalf("expected relationship filter %+v, got %+v", expectedFilter, store.relationshipFilter)
	}
	var body graphResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode graph response: %v", err)
	}
	if body.Depth != 2 || body.Count != 1 || len(body.Nodes) != 2 || len(body.Edges) != 1 {
		t.Fatalf("unexpected graph response: %+v", body)
	}
}

func TestRulesAPIsUseConfiguredRulesAndProvider(t *testing.T) {
	dir := t.TempDir()
	samplesDir := t.TempDir()
	ledgerPath := filepath.Join(dir, "review-ledger.json")
	writeServerRulePack(t, dir, "oss", `{
		"id": "alicloud.oss.server",
		"name": "OSS Server",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS",
		"advice": "Restrict OSS public access."
	}`)
	if err := os.WriteFile(filepath.Join(samplesDir, "oss.json"), []byte(`{"resource_type":"OSS","input":{"bucket":"demo"}}`), 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	if err := os.WriteFile(ledgerPath, []byte(`{"rules":[{"id":"alicloud.oss.server","review_status":"official_reviewed"}]}`), 0o644); err != nil {
		t.Fatalf("write ledger: %v", err)
	}
	handler := NewHandler(nil, WithRulesDir(dir), WithProvider("alicloud"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules?provider=alicloud&severity=high&resource_type=OSS&limit=5", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected rules status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var rulesBody rulesResponse
	if err := json.NewDecoder(rec.Body).Decode(&rulesBody); err != nil {
		t.Fatalf("decode rules response: %v", err)
	}
	if rulesBody.Count != 1 || rulesBody.Rules[0].ID != "alicloud.oss.server" || rulesBody.Provider != "alicloud" {
		t.Fatalf("unexpected rules response: %+v", rulesBody)
	}
	if rulesBody.Total != 1 || rulesBody.Limit != 5 {
		t.Fatalf("unexpected rules pagination metadata: %+v", rulesBody)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/rules/coverage?provider=alicloud&samples="+url.QueryEscape(samplesDir)+"&review_ledger="+url.QueryEscape(ledgerPath), nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected coverage status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var coverageBody struct {
		Provider string `json:"provider"`
		Totals   struct {
			TotalRules         int `json:"total_rules"`
			OfficialReviewed   int `json:"official_reviewed"`
			WithRemediation    int `json:"with_remediation"`
			MissingSampleRefs  int `json:"missing_sample_refs"`
			VerifiedResources  int `json:"verified_resources"`
			MissingRemediation int `json:"missing_remediation"`
		} `json:"totals"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&coverageBody); err != nil {
		t.Fatalf("decode coverage response: %v", err)
	}
	if coverageBody.Provider != "alicloud" || coverageBody.Totals.TotalRules != 1 {
		t.Fatalf("unexpected coverage response: %+v", coverageBody)
	}
	if coverageBody.Totals.OfficialReviewed != 1 || coverageBody.Totals.WithRemediation != 1 || coverageBody.Totals.MissingRemediation != 0 || coverageBody.Totals.MissingSampleRefs != 0 || coverageBody.Totals.VerifiedResources != 1 {
		t.Fatalf("unexpected coverage quality fields: %+v", coverageBody.Totals)
	}
}

func TestRulesAPIPaginatesSearchesAndSorts(t *testing.T) {
	dir := t.TempDir()
	writeServerRulePack(t, dir, "oss-high", `{
		"id": "alicloud.oss.high",
		"name": "OSS High",
		"severity": "high",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`)
	writeServerRulePack(t, dir, "oss-low", `{
		"id": "alicloud.oss.low",
		"name": "OSS Low",
		"severity": "low",
		"provider": "alicloud",
		"asset_type": "OSS"
	}`)
	writeServerRulePack(t, dir, "rds-critical", `{
		"id": "alicloud.rds.critical",
		"name": "RDS Critical",
		"severity": "critical",
		"provider": "alicloud",
		"asset_type": "RDS"
	}`)
	handler := NewHandler(nil, WithRulesDir(dir), WithProvider("alicloud"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules?q=oss&sort=-severity&limit=1&offset=1", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected rules status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var body rulesResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode rules response: %v", err)
	}
	if body.Total != 2 || body.Count != 1 || body.Offset != 1 || body.Limit != 1 {
		t.Fatalf("unexpected paginated rules metadata: %+v", body)
	}
	if body.Rules[0].ID != "alicloud.oss.low" {
		t.Fatalf("expected second OSS rule after severity sort, got %+v", body.Rules)
	}
}

func TestRulesMissingDirReturnsClearError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)

	NewHandler(nil, WithRulesDir(missing)).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
	assertJSONErrorContains(t, rec, "rules directory", "does not exist")
}

func TestRuntimeReportsRulesState(t *testing.T) {
	dir := t.TempDir()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime", nil)

	NewHandler(&recordingStore{}, WithRulesDir(dir), WithProvider("mock"), WithDatabasePath("test.db"), WithVersion("test-version")).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var body runtimeResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode runtime response: %v", err)
	}
	if body.Version != "test-version" || body.Provider != "mock" || body.DatabasePath != "test.db" || !body.StoreConfigured || !body.RulesAvailable {
		t.Fatalf("unexpected runtime response: %+v", body)
	}
}

func TestRuntimeDefaultVersionUsesReleaseSeries(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime", nil)

	NewHandler(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var body runtimeResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode runtime response: %v", err)
	}
	if body.Version == "" || body.Version == "0.0.0-dev" {
		t.Fatalf("default runtime version = %q, want release-series development version", body.Version)
	}
}

func TestFindingsDefaultLimit(t *testing.T) {
	store := &recordingStore{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if store.filter.Limit != defaultFindingsLimit {
		t.Fatalf("expected default limit %d, got %d", defaultFindingsLimit, store.filter.Limit)
	}
}

func TestFindingsInvalidLimit(t *testing.T) {
	store := &recordingStore{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings?limit=nope", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if store.calls != 0 {
		t.Fatalf("expected invalid request to skip store, got %d calls", store.calls)
	}
	assertJSONError(t, rec, "limit must be a positive integer")
}

func TestFindingsRequiresStore(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)

	NewHandler(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}
	assertJSONError(t, rec, "store is not configured")
}

func TestFindingsStoreError(t *testing.T) {
	store := &recordingStore{err: errors.New("database offline")}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)

	NewHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
	assertJSONError(t, rec, "list findings failed")
}

func TestMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/findings", nil)

	NewHandler(&recordingStore{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("expected Allow header %q, got %q", http.MethodGet, allow)
	}
}

type recordingStore struct {
	summary            model.Summary
	summaryFilter      storage.SummaryFilter
	assets             []model.Asset
	assetFilter        storage.AssetFilter
	assetID            string
	findings           []model.Finding
	filter             storage.FindingFilter
	findingID          string
	scanRuns           []model.ScanRun
	scanRunFilter      storage.ScanRunFilter
	relationships      []model.AssetRelationship
	relationshipFilter storage.RelationshipFilter
	err                error
	calls              int
}

func (s *recordingStore) GetSummary(ctx context.Context, filter storage.SummaryFilter) (model.Summary, error) {
	s.summaryFilter = filter
	if s.err != nil {
		return model.Summary{}, s.err
	}
	return s.summary, nil
}

func (s *recordingStore) ListAssets(ctx context.Context, filter storage.AssetFilter) ([]model.Asset, error) {
	s.assetFilter = filter
	if s.err != nil {
		return nil, s.err
	}
	return s.assets, nil
}

func (s *recordingStore) GetAsset(ctx context.Context, id string) (model.Asset, error) {
	s.assetID = id
	if s.err != nil {
		return model.Asset{}, s.err
	}
	for _, asset := range s.assets {
		if asset.ID == id {
			return asset, nil
		}
	}
	return model.Asset{}, sql.ErrNoRows
}

func (s *recordingStore) ListFindings(ctx context.Context, filter storage.FindingFilter) ([]model.Finding, error) {
	s.calls++
	s.filter = filter
	if s.err != nil {
		return nil, s.err
	}
	return s.findings, nil
}

func (s *recordingStore) GetFinding(ctx context.Context, id string) (model.Finding, error) {
	s.findingID = id
	if s.err != nil {
		return model.Finding{}, s.err
	}
	for _, finding := range s.findings {
		if finding.ID == id {
			return finding, nil
		}
	}
	return model.Finding{}, sql.ErrNoRows
}

func (s *recordingStore) ListScanRuns(ctx context.Context, filter storage.ScanRunFilter) ([]model.ScanRun, error) {
	s.scanRunFilter = filter
	if s.err != nil {
		return nil, s.err
	}
	return s.scanRuns, nil
}

func (s *recordingStore) ListAssetRelationships(ctx context.Context, filter storage.RelationshipFilter) ([]model.AssetRelationship, error) {
	s.relationshipFilter = filter
	if s.err != nil {
		return nil, s.err
	}
	return s.relationships, nil
}

func assertContentType(t *testing.T, rec *httptest.ResponseRecorder, expectedPrefix string) {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, expectedPrefix) {
		t.Fatalf("expected Content-Type prefix %q, got %q", expectedPrefix, got)
	}
}

func rawJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return data
}

func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, expected string) {
	t.Helper()

	var body errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error != expected {
		t.Fatalf("expected error %q, got %q", expected, body.Error)
	}
}

func assertJSONErrorContains(t *testing.T, rec *httptest.ResponseRecorder, expectedValues ...string) {
	t.Helper()

	var body errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	for _, expected := range expectedValues {
		if !strings.Contains(body.Error, expected) {
			t.Fatalf("expected error to contain %q, got %q", expected, body.Error)
		}
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func stringSliceFromAny(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
		return values
	default:
		return nil
	}
}

func writeServerRulePack(t *testing.T, root string, name string, metadata string) {
	t.Helper()

	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", dir, err)
	}
	files := map[string]string{
		"metadata.json": metadata,
		"policy.rego":   "package " + name + "\nimport rego.v1\ndefault risk := false\n",
		"input.json":    `{"bucket":"demo"}`,
	}
	for filename, content := range files {
		path := filepath.Join(dir, filename)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}
}
