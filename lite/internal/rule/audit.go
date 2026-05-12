package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
)

const (
	AuditFormatJSON  = "json"
	AuditFormatTable = "table"

	AuditStatusNeedsReview       = "needs_official_review"
	AuditStatusNeedsOfficialDocs = "needs_official_docs"
	AuditStatusOfficialReviewed  = "official_reviewed"
	AuditStatusBlocked           = "blocked"
	AuditStatusNeedsLogicChange  = "needs_logic_change"
)

type AuditOptions struct {
	RulesDir         string
	Provider         string
	OfficialDocs     map[string][]OfficialDoc
	ReviewLedgerPath string
}

type OfficialDoc struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type AuditReport struct {
	Provider string      `json:"provider"`
	Totals   AuditTotals `json:"totals"`
	Rules    []RuleAudit `json:"rules"`
}

type AuditTotals struct {
	TotalRules          int `json:"total_rules"`
	NeedsReview         int `json:"needs_review"`
	NeedsOfficialDocs   int `json:"needs_official_docs"`
	OfficialReviewed    int `json:"official_reviewed"`
	Blocked             int `json:"blocked"`
	NeedsLogicChange    int `json:"needs_logic_change"`
	WithOfficialDocs    int `json:"with_official_docs"`
	WithInputReferences int `json:"with_input_references"`
	WithRemediation     int `json:"with_remediation"`
	MissingRemediation  int `json:"missing_remediation"`
}

type RuleAudit struct {
	ID                  string        `json:"id"`
	Name                string        `json:"name"`
	Provider            string        `json:"provider"`
	ResourceType        string        `json:"resource_type"`
	Severity            string        `json:"severity"`
	ReviewStatus        string        `json:"review_status"`
	PolicySHA256        string        `json:"policy_sha256"`
	LogicSummary        string        `json:"logic_summary"`
	CurrentLogic        string        `json:"current_logic,omitempty"`
	OfficialBehavior    string        `json:"official_behavior,omitempty"`
	ObservedMismatch    string        `json:"observed_mismatch,omitempty"`
	FalsePositiveImpact string        `json:"false_positive_impact,omitempty"`
	FalseNegativeImpact string        `json:"false_negative_impact,omitempty"`
	TestFixture         string        `json:"test_fixture,omitempty"`
	BlockingReason      string        `json:"blocking_reason,omitempty"`
	ReviewedBy          string        `json:"reviewed_by,omitempty"`
	ReviewedAt          string        `json:"reviewed_at,omitempty"`
	InputReferences     []string      `json:"input_references,omitempty"`
	OfficialDocs        []OfficialDoc `json:"official_docs,omitempty"`
	RuleDir             string        `json:"rule_dir,omitempty"`
	HasRemediation      bool          `json:"has_remediation"`
	RemediationSource   string        `json:"remediation_source,omitempty"`
	ChangeRequired      bool          `json:"change_required"`
	ChangeNotes         string        `json:"change_notes,omitempty"`
}

type ReviewLedger struct {
	Rules []RuleReviewRecord `json:"rules"`
}

type RuleReviewRecord struct {
	ID                  string        `json:"id"`
	ResourceType        string        `json:"resource_type,omitempty"`
	Severity            string        `json:"severity,omitempty"`
	PolicySHA256        string        `json:"policy_sha256,omitempty"`
	ReviewStatus        string        `json:"review_status,omitempty"`
	ReviewedBy          string        `json:"reviewed_by,omitempty"`
	ReviewedAt          string        `json:"reviewed_at,omitempty"`
	CurrentLogic        string        `json:"current_logic,omitempty"`
	OfficialBehavior    string        `json:"official_behavior,omitempty"`
	ObservedMismatch    string        `json:"observed_mismatch,omitempty"`
	ProposedChange      string        `json:"proposed_change,omitempty"`
	FalsePositiveImpact string        `json:"false_positive_impact,omitempty"`
	FalseNegativeImpact string        `json:"false_negative_impact,omitempty"`
	TestFixture         string        `json:"test_fixture,omitempty"`
	BlockingReason      string        `json:"blocking_reason,omitempty"`
	ChangeRequired      *bool         `json:"change_required,omitempty"`
	InputReferences     []string      `json:"input_references,omitempty"`
	OfficialDocs        []OfficialDoc `json:"official_docs,omitempty"`
}

func AnalyzeAudit(options AuditOptions) (AuditReport, error) {
	packs, err := LoadDirWithOptions(options.RulesDir, LoadDirOptions{IncludeDisabled: true})
	if err != nil {
		return AuditReport{}, err
	}

	provider := cleanProvider(options.Provider)
	docs := normalizeOfficialDocs(options.OfficialDocs)
	if len(docs) == 0 {
		docs = normalizeOfficialDocs(DefaultOfficialDocs(provider))
	}
	ledger, err := loadReviewLedger(options.ReviewLedgerPath)
	if err != nil {
		return AuditReport{}, err
	}

	rules := make([]RuleAudit, 0, len(packs))
	for _, pack := range packs {
		ruleProvider := cleanProvider(pack.Metadata.Provider)
		if ruleProvider == "" {
			ruleProvider = provider
		}
		if provider != "" && ruleProvider != provider {
			continue
		}

		resourceType := cleanResourceType(firstNonEmpty(pack.Metadata.AssetType, pack.Metadata.Service, "unknown"))
		normalizedResource := normalizeResourceKey(resourceType)
		officialDocs := docs[normalizedResource]
		status := AuditStatusNeedsReview
		if len(officialDocs) == 0 {
			status = AuditStatusNeedsOfficialDocs
		}
		refs := extractInputReferences(pack.Policy)
		row := RuleAudit{
			ID:                pack.Metadata.ID,
			Name:              pack.Metadata.Name,
			Provider:          firstNonEmpty(ruleProvider, "unknown"),
			ResourceType:      resourceType,
			Severity:          string(pack.Metadata.Severity),
			ReviewStatus:      status,
			PolicySHA256:      policySHA256(pack.Policy),
			LogicSummary:      logicSummary(pack.Policy, refs),
			InputReferences:   refs,
			OfficialDocs:      officialDocs,
			RuleDir:           pack.Dir,
			HasRemediation:    ruleHasRemediation(pack),
			RemediationSource: remediationSource(pack),
		}
		if record, ok := ledger[pack.Metadata.ID]; ok {
			applyReviewRecord(&row, record)
		}
		rules = append(rules, row)
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].ResourceType != rules[j].ResourceType {
			return rules[i].ResourceType < rules[j].ResourceType
		}
		return rules[i].ID < rules[j].ID
	})

	report := AuditReport{
		Provider: provider,
		Rules:    rules,
	}
	report.Totals.TotalRules = len(rules)
	for _, item := range rules {
		if item.ReviewStatus == AuditStatusNeedsReview {
			report.Totals.NeedsReview++
		}
		if item.ReviewStatus == AuditStatusNeedsOfficialDocs {
			report.Totals.NeedsOfficialDocs++
		}
		if item.ReviewStatus == AuditStatusOfficialReviewed {
			report.Totals.OfficialReviewed++
		}
		if item.ReviewStatus == AuditStatusBlocked {
			report.Totals.Blocked++
		}
		if item.ReviewStatus == AuditStatusNeedsLogicChange {
			report.Totals.NeedsLogicChange++
		}
		if len(item.OfficialDocs) > 0 {
			report.Totals.WithOfficialDocs++
		}
		if len(item.InputReferences) > 0 {
			report.Totals.WithInputReferences++
		}
		if item.HasRemediation {
			report.Totals.WithRemediation++
		} else {
			report.Totals.MissingRemediation++
		}
	}
	return report, nil
}

func RenderAudit(w io.Writer, report AuditReport, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", AuditFormatTable:
		return renderAuditTable(w, report)
	case AuditFormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	default:
		return fmt.Errorf("unknown audit format %q", format)
	}
}

func renderAuditTable(w io.Writer, report AuditReport) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "Provider\tResource Type\tRule ID\tSeverity\tStatus\tDocs\tRefs\tRemediation\tPolicy SHA256"); err != nil {
		return err
	}
	for _, item := range report.Rules {
		remediation := item.RemediationSource
		if remediation == "" {
			remediation = "missing"
		}
		if _, err := fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n",
			item.Provider,
			item.ResourceType,
			item.ID,
			item.Severity,
			item.ReviewStatus,
			len(item.OfficialDocs),
			len(item.InputReferences),
			remediation,
			shortHash(item.PolicySHA256),
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(
		tw,
		"\nTotals\t%d rules\t%d needs review\t%d missing docs\t%d official reviewed\t%d blocked\t%d needs logic change\t%d with docs\t%d with refs\t%d with remediation\t%d missing remediation\t\n",
		report.Totals.TotalRules,
		report.Totals.NeedsReview,
		report.Totals.NeedsOfficialDocs,
		report.Totals.OfficialReviewed,
		report.Totals.Blocked,
		report.Totals.NeedsLogicChange,
		report.Totals.WithOfficialDocs,
		report.Totals.WithInputReferences,
		report.Totals.WithRemediation,
		report.Totals.MissingRemediation,
	); err != nil {
		return err
	}
	return tw.Flush()
}

func DefaultOfficialDocs(provider string) map[string][]OfficialDoc {
	if cleanProvider(provider) != "alicloud" {
		return nil
	}
	genericRAMPolicy := OfficialDoc{
		Title: "Alibaba Cloud RAM policy elements and condition keys",
		URL:   "https://www.alibabacloud.com/help/en/ram/user-guide/policy-elements",
	}
	genericRiskConfig := OfficialDoc{
		Title: "Alibaba Cloud resource access-control documentation index",
		URL:   "https://www.alibabacloud.com/help/en/",
	}
	return map[string][]OfficialDoc{
		"account":              {genericRAMPolicy},
		"ramuser":              {genericRAMPolicy},
		"ramrole":              {genericRAMPolicy},
		"oss":                  {genericRAMPolicy, {Title: "Alibaba Cloud OSS public access and bucket policy documentation", URL: "https://www.alibabacloud.com/help/en/oss/"}},
		"sls":                  {genericRAMPolicy, {Title: "Alibaba Cloud Simple Log Service authorization documentation", URL: "https://www.alibabacloud.com/help/en/sls/"}},
		"ecs":                  {genericRAMPolicy, genericRiskConfig},
		"securitygroup":        {genericRAMPolicy, genericRiskConfig},
		"slb":                  {genericRAMPolicy, genericRiskConfig},
		"alb":                  {genericRAMPolicy, genericRiskConfig},
		"nlb":                  {genericRAMPolicy, genericRiskConfig},
		"rds":                  {genericRAMPolicy, {Title: "Alibaba Cloud RDS network and whitelist documentation", URL: "https://www.alibabacloud.com/help/en/rds/"}},
		"redis":                {genericRAMPolicy, {Title: "Alibaba Cloud Tair/Redis network security documentation", URL: "https://www.alibabacloud.com/help/en/redis/"}},
		"mongodb":              {genericRAMPolicy, {Title: "Alibaba Cloud MongoDB network security documentation", URL: "https://www.alibabacloud.com/help/en/mongodb/"}},
		"polardb":              {genericRAMPolicy, {Title: "Alibaba Cloud PolarDB network security documentation", URL: "https://www.alibabacloud.com/help/en/polardb/"}},
		"clickhouse":           {genericRAMPolicy, {Title: "Alibaba Cloud ClickHouse network security documentation", URL: "https://www.alibabacloud.com/help/en/clickhouse/"}},
		"nas":                  {genericRAMPolicy, genericRiskConfig},
		"ackcluster":           {genericRAMPolicy, {Title: "Alibaba Cloud Container Service for Kubernetes documentation", URL: "https://www.alibabacloud.com/help/en/ack/"}},
		"acr":                  {genericRAMPolicy, {Title: "Alibaba Cloud Container Registry documentation", URL: "https://www.alibabacloud.com/help/en/acr/"}},
		"actiontrail":          {genericRAMPolicy, {Title: "Alibaba Cloud ActionTrail documentation", URL: "https://www.alibabacloud.com/help/en/actiontrail/"}},
		"analyticdbpostgresql": {genericRAMPolicy, {Title: "Alibaba Cloud AnalyticDB for PostgreSQL documentation", URL: "https://www.alibabacloud.com/help/en/analyticdb-for-postgresql/"}},
		"cert":                 {genericRAMPolicy, {Title: "Alibaba Cloud Certificate Management Service documentation", URL: "https://www.alibabacloud.com/help/en/ssl-certificate/"}},
		"cloudfw":              {genericRAMPolicy, {Title: "Alibaba Cloud Cloud Firewall documentation", URL: "https://www.alibabacloud.com/help/en/cloud-firewall/"}},
		"cloudfwconfig":        {genericRAMPolicy, {Title: "Alibaba Cloud Cloud Firewall documentation", URL: "https://www.alibabacloud.com/help/en/cloud-firewall/"}},
		"ecicontainergroup":    {genericRAMPolicy, {Title: "Alibaba Cloud Elastic Container Instance documentation", URL: "https://www.alibabacloud.com/help/en/eci/"}},
		"ecsimage":             {genericRAMPolicy, {Title: "Alibaba Cloud ECS image documentation", URL: "https://www.alibabacloud.com/help/en/ecs/"}},
		"elasticsearch":        {genericRAMPolicy, {Title: "Alibaba Cloud Elasticsearch documentation", URL: "https://www.alibabacloud.com/help/en/es/"}},
		"ensinstance":          {genericRAMPolicy, {Title: "Alibaba Cloud ENS documentation", URL: "https://www.alibabacloud.com/help/en/ens/"}},
		"ensnatgateway":        {genericRAMPolicy, {Title: "Alibaba Cloud ENS documentation", URL: "https://www.alibabacloud.com/help/en/ens/"}},
		"hbase":                {genericRAMPolicy, {Title: "Alibaba Cloud HBase documentation", URL: "https://www.alibabacloud.com/help/en/hbase/"}},
		"kafka":                {genericRAMPolicy, {Title: "Alibaba Cloud ApsaraMQ for Kafka documentation", URL: "https://www.alibabacloud.com/help/en/apsaramq-for-kafka/"}},
		"lindorm":              {genericRAMPolicy, {Title: "Alibaba Cloud Lindorm documentation", URL: "https://www.alibabacloud.com/help/en/lindorm/"}},
		"maxcompute":           {genericRAMPolicy, {Title: "Alibaba Cloud MaxCompute documentation", URL: "https://www.alibabacloud.com/help/en/maxcompute/"}},
		"nat":                  {genericRAMPolicy, {Title: "Alibaba Cloud NAT Gateway documentation", URL: "https://www.alibabacloud.com/help/en/nat-gateway/"}},
		"rocketmq":             {genericRAMPolicy, {Title: "Alibaba Cloud ApsaraMQ for RocketMQ documentation", URL: "https://www.alibabacloud.com/help/en/apsaramq-for-rocketmq/"}},
		"sas":                  {genericRAMPolicy, {Title: "Alibaba Cloud Security Center documentation", URL: "https://www.alibabacloud.com/help/en/security-center/"}},
		"cdn":                  {genericRAMPolicy, genericRiskConfig},
		"waf":                  {genericRAMPolicy, genericRiskConfig},
		"fc":                   {genericRAMPolicy, genericRiskConfig},
	}
}

func normalizeOfficialDocs(input map[string][]OfficialDoc) map[string][]OfficialDoc {
	output := map[string][]OfficialDoc{}
	for resourceType, docs := range input {
		key := normalizeResourceKey(resourceType)
		if key == "" {
			continue
		}
		cleanDocs := make([]OfficialDoc, 0, len(docs))
		for _, doc := range docs {
			doc.Title = strings.TrimSpace(doc.Title)
			doc.URL = strings.TrimSpace(doc.URL)
			if doc.Title == "" || doc.URL == "" {
				continue
			}
			cleanDocs = append(cleanDocs, doc)
		}
		if len(cleanDocs) > 0 {
			output[key] = append(output[key], cleanDocs...)
		}
	}
	return output
}

func policySHA256(policy string) string {
	sum := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(sum[:])
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

func extractInputReferences(policy string) []string {
	re := regexp.MustCompile(`\binput(?:\.[A-Za-z_][A-Za-z0-9_]*)+`)
	matches := re.FindAllString(policy, -1)
	refs := make([]string, 0, len(matches))
	for _, match := range matches {
		ref := strings.TrimSpace(strings.TrimPrefix(match, "input."))
		if ref != "" {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return uniqueAuditStrings(refs)
}

func logicSummary(policy string, refs []string) string {
	signals := []string{}
	if strings.Contains(policy, "Principal") {
		signals = append(signals, "principal")
	}
	if strings.Contains(policy, "Condition") {
		signals = append(signals, "condition")
	}
	if strings.Contains(policy, "0.0.0.0/0") || strings.Contains(policy, "::/0") {
		signals = append(signals, "public_cidr")
	}
	if strings.Contains(policy, "json.unmarshal") {
		signals = append(signals, "json_policy")
	}
	if len(refs) > 0 {
		signals = append(signals, fmt.Sprintf("%d_input_refs", len(refs)))
	}
	if len(signals) == 0 {
		return "requires manual review"
	}
	return strings.Join(signals, ", ")
}

func uniqueAuditStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func loadReviewLedger(path string) (map[string]RuleReviewRecord, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return map[string]RuleReviewRecord{}, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]RuleReviewRecord{}, nil
		}
		return nil, fmt.Errorf("read review ledger %q: %w", path, err)
	}
	var ledger ReviewLedger
	if err := json.Unmarshal(content, &ledger); err == nil && len(ledger.Rules) > 0 {
		return indexReviewRecords(ledger.Rules), nil
	}
	var byID map[string]RuleReviewRecord
	if err := json.Unmarshal(content, &byID); err != nil {
		return nil, fmt.Errorf("decode review ledger %q: %w", path, err)
	}
	records := make([]RuleReviewRecord, 0, len(byID))
	for id, record := range byID {
		if record.ID == "" {
			record.ID = id
		}
		records = append(records, record)
	}
	return indexReviewRecords(records), nil
}

func indexReviewRecords(records []RuleReviewRecord) map[string]RuleReviewRecord {
	index := map[string]RuleReviewRecord{}
	for _, record := range records {
		record.ID = strings.TrimSpace(record.ID)
		if record.ID == "" {
			continue
		}
		index[record.ID] = record
	}
	return index
}

func applyReviewRecord(row *RuleAudit, record RuleReviewRecord) {
	if row == nil {
		return
	}
	if status := normalizeAuditStatus(record.ReviewStatus); status != "" {
		row.ReviewStatus = status
	} else if strings.TrimSpace(record.BlockingReason) != "" {
		row.ReviewStatus = AuditStatusBlocked
	}
	row.ReviewedBy = strings.TrimSpace(record.ReviewedBy)
	row.ReviewedAt = strings.TrimSpace(record.ReviewedAt)
	row.CurrentLogic = strings.TrimSpace(record.CurrentLogic)
	row.OfficialBehavior = strings.TrimSpace(record.OfficialBehavior)
	row.ObservedMismatch = strings.TrimSpace(record.ObservedMismatch)
	row.FalsePositiveImpact = strings.TrimSpace(record.FalsePositiveImpact)
	row.FalseNegativeImpact = strings.TrimSpace(record.FalseNegativeImpact)
	row.TestFixture = strings.TrimSpace(record.TestFixture)
	row.BlockingReason = strings.TrimSpace(record.BlockingReason)
	row.ChangeNotes = strings.TrimSpace(record.ProposedChange)
	if record.ChangeRequired != nil {
		row.ChangeRequired = *record.ChangeRequired
	} else if row.ChangeNotes != "" {
		row.ChangeRequired = true
	}
	if docs := normalizeOfficialDocs(map[string][]OfficialDoc{row.ResourceType: record.OfficialDocs}); len(docs) > 0 {
		row.OfficialDocs = docs[normalizeResourceKey(row.ResourceType)]
	}
}

func normalizeAuditStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case AuditStatusNeedsReview:
		return AuditStatusNeedsReview
	case AuditStatusNeedsOfficialDocs:
		return AuditStatusNeedsOfficialDocs
	case AuditStatusOfficialReviewed:
		return AuditStatusOfficialReviewed
	case AuditStatusBlocked:
		return AuditStatusBlocked
	case AuditStatusNeedsLogicChange:
		return AuditStatusNeedsLogicChange
	default:
		return ""
	}
}

func ruleHasRemediation(pack RulePack) bool {
	return remediationSource(pack) != ""
}

func remediationSource(pack RulePack) string {
	if strings.TrimSpace(pack.Remediation) != "" {
		return "remediation.md"
	}
	if strings.TrimSpace(pack.Metadata.Advice) != "" {
		return "metadata.advice"
	}
	if strings.TrimSpace(pack.Metadata.Link) != "" {
		return "metadata.link"
	}
	return ""
}
