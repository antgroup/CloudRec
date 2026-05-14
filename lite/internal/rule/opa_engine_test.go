package rule

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOPAEngineEvaluatesSamplePackExamples(t *testing.T) {
	packs, err := LoadDir(sampleRulesDir(t))
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}
	pack := findSamplePack(t, packs)

	evaluator := NewEvaluator(NewOPAEngine())
	for _, example := range pack.Examples {
		input, err := example.InputValue()
		if err != nil {
			t.Fatalf("InputValue(%q) error = %v", example.Name, err)
		}

		findings, err := evaluator.Evaluate(context.Background(), []RulePack{pack}, input)
		if err != nil {
			t.Fatalf("Evaluate(%q) error = %v", example.Name, err)
		}
		if len(findings) != example.WantFindings {
			t.Fatalf("Evaluate(%q) findings = %d, want %d", example.Name, len(findings), example.WantFindings)
		}
		if example.WantFindings == 0 {
			continue
		}

		finding := findings[0]
		if finding.RuleID != pack.Metadata.ID {
			t.Fatalf("finding rule_id = %q, want %q", finding.RuleID, pack.Metadata.ID)
		}
		if finding.AssetID != "bucket-public" {
			t.Fatalf("finding asset_id = %q", finding.AssetID)
		}
		if finding.Evidence["public"] != true {
			t.Fatalf("finding evidence public = %#v", finding.Evidence["public"])
		}
		if finding.Remediation == "" {
			t.Fatal("finding remediation is empty")
		}
	}
}

func TestOPAEngineEvaluatesLegacyRiskBool(t *testing.T) {
	pack := RulePack{
		Metadata: RuleMetadata{
			ID:        "ALI_CLOUD_OSS_legacy",
			Name:      "Legacy OSS risk",
			Severity:  SeverityHigh,
			Provider:  "ALI_CLOUD",
			Service:   "OSS",
			AssetType: "OSS",
			Advice:    "Restrict public access.",
		},
		PolicyPath: "legacy.rego",
		Policy: `package legacy_oss
import rego.v1

default risk := false

risk if {
	input.public == true
}`,
	}

	findings, err := NewEvaluator(NewOPAEngine()).Evaluate(context.Background(), []RulePack{pack}, map[string]any{"public": true})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].RuleID != pack.Metadata.ID {
		t.Fatalf("finding rule_id = %q", findings[0].RuleID)
	}
	if findings[0].Remediation != "Restrict public access." {
		t.Fatalf("finding remediation = %q", findings[0].Remediation)
	}
}

func TestOPAEngineEvaluatesAlicloudOSSPublicPolicyRule(t *testing.T) {
	policy, err := os.ReadFile(filepath.Join("..", "..", "rules", "alicloud", "ALI_CLOUD_OSS_202501081111_563734", "policy.rego"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	pack := RulePack{
		Metadata: RuleMetadata{
			ID:        "ALI_CLOUD_OSS_202501081111_563734",
			Name:      "OSS public bucket policy",
			Severity:  SeverityHigh,
			Provider:  "alicloud",
			Service:   "oss",
			AssetType: "oss",
			Query:     "data.oss_bucket_anony_access_2200008.risk",
		},
		PolicyPath: "oss_public_policy.rego",
		Policy:     string(policy),
	}
	evaluator := NewEvaluator(NewOPAEngine())
	cases := []struct {
		name         string
		input        map[string]any
		wantFindings int
	}{
		{
			name: "official policy status public",
			input: ossPolicyInput(map[string]any{
				"BucketPolicyStatus": map[string]any{"IsPublic": true},
			}),
			wantFindings: 1,
		},
		{
			name: "block public access suppresses public status",
			input: ossPolicyInput(map[string]any{
				"BucketInfo":         map[string]any{"BlockPublicAccess": true},
				"BucketPolicyStatus": map[string]any{"IsPublic": true},
			}),
			wantFindings: 0,
		},
		{
			name: "public principal without condition",
			input: ossPolicyInput(map[string]any{
				"BucketPolicy": map[string]any{"Statement": []any{map[string]any{
					"Effect":    "Allow",
					"Principal": []any{"*"},
					"Action":    []any{"oss:GetObject"},
				}}},
			}),
			wantFindings: 1,
		},
		{
			name: "fixed source vpc is not public",
			input: ossPolicyInput(map[string]any{
				"BucketPolicy": map[string]any{"Statement": []any{map[string]any{
					"Effect":    "Allow",
					"Principal": []any{"*"},
					"Condition": map[string]any{"StringEquals": map[string]any{"acs:SourceVpc": []any{"vpc-abc123"}}},
				}}},
			}),
			wantFindings: 0,
		},
		{
			name: "wildcard source vpc remains public",
			input: ossPolicyInput(map[string]any{
				"BucketPolicy": map[string]any{"Statement": []any{map[string]any{
					"Effect":    "Allow",
					"Principal": []any{"*"},
					"Condition": map[string]any{"StringLike": map[string]any{"acs:SourceVpc": []any{"vpc-*"}}},
				}}},
			}),
			wantFindings: 1,
		},
		{
			name: "source ip all internet remains public",
			input: ossPolicyInput(map[string]any{
				"BucketPolicy": map[string]any{"Statement": []any{map[string]any{
					"Effect":    "Allow",
					"Principal": []any{"*"},
					"Condition": map[string]any{"IpAddress": map[string]any{"acs:SourceIp": []any{"0.0.0.0/0"}}},
				}}},
			}),
			wantFindings: 1,
		},
		{
			name: "narrow source ip is not public",
			input: ossPolicyInput(map[string]any{
				"BucketPolicy": map[string]any{"Statement": []any{map[string]any{
					"Effect":    "Allow",
					"Principal": []any{"*"},
					"Condition": map[string]any{"IpAddress": map[string]any{"acs:SourceIp": []any{"10.0.0.0/8"}}},
				}}},
			}),
			wantFindings: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := evaluator.Evaluate(context.Background(), []RulePack{pack}, tc.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(findings) != tc.wantFindings {
				t.Fatalf("findings = %d, want %d", len(findings), tc.wantFindings)
			}
		})
	}
}

func TestOPAEngineEvaluatesAlicloudCloudFWOutboundRule(t *testing.T) {
	policy, err := os.ReadFile(filepath.Join("..", "..", "rules", "alicloud", "ALI_CLOUD_Cloudfw_202501081111_104298", "policy.rego"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	pack := RulePack{
		Metadata: RuleMetadata{
			ID:        "ALI_CLOUD_Cloudfw_202501081111_104298",
			Name:      "CloudFW broad outbound allow",
			Severity:  SeverityLow,
			Provider:  "alicloud",
			Service:   "cloudfw",
			AssetType: "cloudfw",
			Query:     "data.cloudfw_forbidden_net_out_by_default_2400001.risk",
		},
		PolicyPath: "cloudfw_outbound.rego",
		Policy:     string(policy),
	}
	evaluator := NewEvaluator(NewOPAEngine())
	cases := []struct {
		name         string
		policy       map[string]any
		wantFindings int
	}{
		{
			name: "outbound allow to internet",
			policy: map[string]any{
				"Direction":   "out",
				"AclAction":   "accept",
				"Proto":       "TCP",
				"DestPort":    "443",
				"Destination": "0.0.0.0/0",
			},
			wantFindings: 1,
		},
		{
			name: "inbound allow is handled by topology exposure logic",
			policy: map[string]any{
				"Direction":   "in",
				"AclAction":   "accept",
				"Proto":       "TCP",
				"DestPort":    "443",
				"Destination": "0.0.0.0/0",
			},
			wantFindings: 0,
		},
		{
			name: "outbound drop is not risky",
			policy: map[string]any{
				"Direction":   "out",
				"AclAction":   "drop",
				"Proto":       "Any",
				"DestPort":    "Any",
				"Destination": "0.0.0.0/0",
			},
			wantFindings: 0,
		},
		{
			name: "dns and ntp exceptions are ignored",
			policy: map[string]any{
				"Direction":   "out",
				"AclAction":   "accept",
				"Proto":       "UDP",
				"DestPort":    "53/53",
				"Destination": "0.0.0.0/0",
			},
			wantFindings: 0,
		},
		{
			name: "specific destination is not broad internet egress",
			policy: map[string]any{
				"Direction":   "out",
				"AclAction":   "accept",
				"Proto":       "TCP",
				"DestPort":    "443",
				"Destination": "10.0.0.0/8",
			},
			wantFindings: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := evaluator.Evaluate(context.Background(), []RulePack{pack}, map[string]any{"Policy": tc.policy})
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(findings) != tc.wantFindings {
				t.Fatalf("findings = %d, want %d", len(findings), tc.wantFindings)
			}
		})
	}
}

func TestOPAEngineEvaluatesAlicloudENSAgentRule(t *testing.T) {
	policy, err := os.ReadFile(filepath.Join("..", "..", "rules", "alicloud", "ALI_CLOUD_ENS Instance_202501241146_999147", "policy.rego"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	pack := RulePack{
		Metadata: RuleMetadata{
			ID:        "ALI_CLOUD_ENS Instance_202501241146_999147",
			Name:      "ENS Security Center agent missing or offline",
			Severity:  SeverityMedium,
			Provider:  "alicloud",
			Service:   "ens",
			AssetType: "ens_instance",
			Query:     "data.ens_instance_didnt_install_aegis_5600001.risk",
		},
		PolicyPath: "ens_agent.rego",
		Policy:     string(policy),
	}
	evaluator := NewEvaluator(NewOPAEngine())
	cases := []struct {
		name         string
		input        map[string]any
		wantFindings int
	}{
		{
			name: "missing linked evidence does not alert",
			input: map[string]any{
				"Instance": map[string]any{"InstanceId": "i-1"},
			},
			wantFindings: 0,
		},
		{
			name: "offline linked agent alerts",
			input: ensAgentInput(map[string]any{
				"ClientStatus": "offline",
				"AuthVersion":  1,
			}),
			wantFindings: 1,
		},
		{
			name: "online lower edition does not alert",
			input: ensAgentInput(map[string]any{
				"ClientStatus": "online",
				"AuthVersion":  1,
			}),
			wantFindings: 0,
		},
		{
			name: "uninstalled sub status alerts",
			input: ensAgentInput(map[string]any{
				"ClientSubStatus": "uninstalled",
				"AuthVersion":     7,
			}),
			wantFindings: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := evaluator.Evaluate(context.Background(), []RulePack{pack}, tc.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(findings) != tc.wantFindings {
				t.Fatalf("findings = %d, want %d", len(findings), tc.wantFindings)
			}
		})
	}
}

func ossPolicyInput(overrides map[string]any) map[string]any {
	input := map[string]any{
		"BucketInfo":       map[string]any{"BlockPublicAccess": false},
		"BucketProperties": map[string]any{"Name": "bucket-demo"},
	}
	for key, value := range overrides {
		input[key] = value
	}
	return input
}

func ensAgentInput(agentFields map[string]any) map[string]any {
	return map[string]any{
		"Instance": map[string]any{
			"InstanceId": "i-ens",
		},
		"InstanceInstalledAegis": map[string]any{
			"Instance": agentFields,
		},
	}
}

func TestOPAEngineLoadsRelationData(t *testing.T) {
	root := t.TempDir()
	writeRuleFile(t, root, "data/risk_default_ports.json", `{
		"risk_default_ports": {
			"servicePorts": [
				{"port": 22, "service": "SSH"}
			]
		}
	}`)
	writeRuleFile(t, root, "ALI_CLOUD/ecs-risk-port/metadata.json", `{
		"code": "ALI_CLOUD_ECS_202501081111_432000",
		"level": "High",
		"name": "阿里云-ECS-实例安全组对公网开放高危端口",
		"platform": "ALI_CLOUD",
		"resourceType": "ECS"
	}`)
	writeRuleFile(t, root, "ALI_CLOUD/ecs-risk-port/relation.json", `["risk_default_ports"]`)
	writeRuleFile(t, root, "ALI_CLOUD/ecs-risk-port/policy.rego", `package ecs_open_risk_port_to_pub
import rego.v1

default risk := false

servicePorts := data.risk_default_ports.servicePorts

risk if {
	some servicePort in servicePorts
	servicePort.port == input.port
}`)

	packs, err := LoadDir(root)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("packs = %d, want 1", len(packs))
	}
	if len(packs[0].DataPaths) != 1 {
		t.Fatalf("data paths = %#v", packs[0].DataPaths)
	}
	if _, ok := packs[0].Data["risk_default_ports"]; !ok {
		t.Fatalf("data.risk_default_ports was not loaded: %#v", packs[0].Data)
	}

	findings, err := NewEvaluator(NewOPAEngine()).Evaluate(context.Background(), packs, map[string]any{"port": 22})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].RuleID != "ALI_CLOUD_ECS_202501081111_432000" {
		t.Fatalf("finding rule_id = %q", findings[0].RuleID)
	}
}
