package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/antgroup/CloudRec/lite/internal/core"
	"github.com/antgroup/CloudRec/lite/internal/report"
	"github.com/antgroup/CloudRec/lite/internal/rule"
	"github.com/antgroup/CloudRec/lite/internal/server"
	"github.com/antgroup/CloudRec/lite/internal/storage"
	"github.com/antgroup/CloudRec/lite/providers/alicloud"
)

var version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "scan":
		return runScan(args[1:])
	case "rules":
		return runRules(args[1:])
	case "dashboard":
		return runDashboard(args[1:])
	case "risks", "findings":
		return runRisks(args[1:])
	case "assets":
		return runAssets(args[1:])
	case "scans":
		return runScans(args[1:])
	case "facets":
		return runFacets(args[1:])
	case "credentials":
		return runCredentials(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "export":
		return runExport(args[1:])
	case "serve":
		return runServe(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runRules(args []string) error {
	return runRulesWithWriter(args, os.Stdout)
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	provider := fs.String("provider", "mock", "cloud provider to scan")
	account := fs.String("account", "default", "account identifier or profile")
	region := fs.String("region", "", "default cloud region")
	regions := fs.String("regions", "", "comma-separated cloud regions to scan; --region takes precedence when both are set")
	resourceTypes := fs.String("resource-types", "", "comma-separated cloud resource types to collect")
	rules := fs.String("rules", "./rules", "rule pack directory")
	db := fs.String("db", core.DefaultDBPath(), "SQLite database path")
	dryRun := fs.Bool("dry-run", true, "run without persisting scan output")
	output := fs.String("output", report.FormatText, "output format: text or json")
	fixture := fs.String("fixture", "", "local provider fixture path for development scans")
	envFile := fs.String("env-file", "", "optional plaintext env file fallback for credentials; missing files are ignored")
	credentialSource := fs.String("credential-source", alicloud.CredentialSourceAuto, "credential source: auto, keyring, file, or env")
	credentialProfile := fs.String("credential-profile", "", "system credential store profile; defaults to --account")
	skipAccountValidation := fs.Bool("skip-account-validation", false, "skip live provider account validation before collection")
	collectorLogLevel := fs.String("collector-log-level", "silent", "legacy collector log level: silent, error, warn, info, or debug")
	collectorTimeout := fs.String("collector-timeout", "", "per resource-region collector timeout, such as 60s or 2m")
	collectorConcurrency := fs.Int("collector-concurrency", 4, "maximum concurrent resource-region collector tasks")
	collectorSkipCacheTTL := fs.String("collector-skip-cache-ttl", "24h", "cache TTL for stable unsupported/disabled/permission collector skips; use 0s to disable")
	maxComputeTenantID := fs.String("maxcompute-tenant-id", "", "optional MaxCompute tenant ID for ListProjects")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := loadEnvFile(*envFile); err != nil {
		return err
	}

	config := map[string]string{}
	if *fixture != "" {
		config["fixture"] = *fixture
	}
	if *resourceTypes != "" {
		config["resource_types"] = *resourceTypes
	}
	if *regions != "" {
		config["regions"] = *regions
	}
	if *skipAccountValidation {
		config["skip_account_validation"] = "true"
	}
	if *collectorLogLevel != "" {
		config["collector_log_level"] = *collectorLogLevel
	}
	if *collectorTimeout != "" {
		config["collector_timeout"] = *collectorTimeout
	}
	if *collectorConcurrency > 0 {
		config["collector_concurrency"] = fmt.Sprint(*collectorConcurrency)
	}
	if *collectorSkipCacheTTL != "" {
		config["collector_skip_cache_ttl"] = *collectorSkipCacheTTL
	}
	if *maxComputeTenantID != "" {
		config["maxcompute_tenant_id"] = *maxComputeTenantID
	}
	if *credentialSource != "" {
		config[alicloud.ConfigCredentialSource] = alicloud.NormalizeCredentialSource(*credentialSource)
	}
	if *credentialProfile != "" {
		config[alicloud.ConfigCredentialProfile] = *credentialProfile
	}

	scanner := core.NewScanner()
	result, err := scanner.Scan(core.ScanOptions{
		Provider: *provider,
		Account:  *account,
		Region:   *region,
		RulesDir: *rules,
		DBPath:   *db,
		DryRun:   *dryRun,
		Config:   config,
		Progress: os.Stderr,
	})
	if err != nil {
		return err
	}

	return report.RenderScanResult(os.Stdout, result, *output)
}

func runServe(args []string) error {
	config, err := parseServeConfig(args)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if err := core.EnsureDBParentDir(config.DBPath); err != nil {
		return err
	}
	store, err := storage.Open(ctx, config.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.Init(ctx); err != nil {
		return err
	}

	fmt.Printf("CloudRec Lite serving http://%s using db=%s rules=%s provider=%s\n", config.Addr, config.DBPath, config.RulesDir, config.Provider)
	return http.ListenAndServe(config.Addr, server.NewHandler(
		store,
		server.WithRulesDir(config.RulesDir),
		server.WithProvider(config.Provider),
		server.WithDatabasePath(config.DBPath),
		server.WithVersion(version),
	))
}

type serveConfig struct {
	Addr     string
	DBPath   string
	RulesDir string
	Provider string
}

func parseServeConfig(args []string) (serveConfig, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8787", "listen address")
	db := fs.String("db", core.DefaultDBPath(), "SQLite database path")
	rules := fs.String("rules", "./rules", "rule pack directory for web rules APIs")
	provider := fs.String("provider", "alicloud", "cloud provider for web rules APIs")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}
	config := serveConfig{
		Addr:     *addr,
		DBPath:   core.NormalizeDBPath(*db),
		RulesDir: *rules,
		Provider: *provider,
	}
	if err := server.ValidateRulesDir(config.RulesDir); err != nil {
		return serveConfig{}, err
	}
	return config, nil
}

func runRulesCoverage(args []string) error {
	return runRulesCoverageWithWriter(args, os.Stdout)
}

func runRulesAudit(args []string) error {
	return runRulesAuditWithWriter(args, os.Stdout)
}

func runRulesValidate(args []string) error {
	return runRulesValidateWithWriter(args, os.Stdout)
}

func runRulesValidateWithWriter(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("rules validate", flag.ContinueOnError)
	rules := fs.String("rules", "./rules/alicloud", "rule pack directory")
	provider := fs.String("provider", "alicloud", "cloud provider to validate")
	format := fs.String("format", rule.ValidationFormatTable, "output format: table or json")
	samples := fs.String("samples", "", "optional directory of real collector/native-adapter field samples")
	if err := fs.Parse(args); err != nil {
		return err
	}

	report, err := rule.AnalyzeValidation(context.Background(), rule.ValidationOptions{
		RulesDir:   *rules,
		Provider:   *provider,
		SamplesDir: *samples,
	})
	if err != nil {
		return err
	}
	return rule.RenderValidation(w, report, *format)
}

func runRulesAuditWithWriter(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("rules audit", flag.ContinueOnError)
	rules := fs.String("rules", "./rules/alicloud", "rule pack directory")
	provider := fs.String("provider", "alicloud", "cloud provider to audit")
	format := fs.String("format", rule.AuditFormatTable, "output format: table or json")
	reviewLedger := fs.String("review-ledger", "", "optional review ledger JSON to merge into audit output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	report, err := rule.AnalyzeAudit(rule.AuditOptions{
		RulesDir:         *rules,
		Provider:         *provider,
		ReviewLedgerPath: *reviewLedger,
	})
	if err != nil {
		return err
	}
	return rule.RenderAudit(w, report, *format)
}

func runRulesCoverageWithWriter(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("rules coverage", flag.ContinueOnError)
	rules := fs.String("rules", "./rules/alicloud", "rule pack directory")
	provider := fs.String("provider", "alicloud", "cloud provider catalog to use")
	format := fs.String("format", rule.CoverageFormatTable, "output format: table or json")
	samples := fs.String("samples", "", "optional directory of real collector/native-adapter field samples")
	reviewLedger := fs.String("review-ledger", "", "optional review ledger JSON to merge into coverage output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	options := rule.CoverageOptions{
		RulesDir:         *rules,
		Provider:         *provider,
		SamplesDir:       *samples,
		ReviewLedgerPath: *reviewLedger,
	}
	if *provider == "alicloud" {
		options.Catalog = alicloudCoverageCatalog()
		options.NativeAdapters = alicloudNativeAdapterMap()
	}

	report, err := rule.AnalyzeCoverage(options)
	if err != nil {
		return err
	}
	return rule.RenderCoverage(w, report, *format)
}

func alicloudCoverageCatalog() []rule.CoverageCatalogSpec {
	specs := alicloud.AllResourceSpecs()
	catalog := make([]rule.CoverageCatalogSpec, 0, len(specs))
	for _, spec := range specs {
		catalog = append(catalog, rule.CoverageCatalogSpec{
			Type:       spec.Type,
			Normalized: spec.Normalized,
			Group:      spec.Group,
			Dimension:  spec.Dimension,
		})
	}
	return catalog
}

func alicloudNativeAdapterMap() map[string]bool {
	adapters := map[string]bool{}
	for _, resourceType := range alicloud.NativeAdapterResourceTypes() {
		adapters[resourceType] = true
	}
	return adapters
}

func printUsage() {
	fmt.Println(`CloudRec Lite

Usage:
  cloudrec-lite version
  cloudrec-lite credentials store [--provider alicloud] [--account 123456789|--profile prod] [--access-key-id-stdin|--access-key-id <ak-id>] [--secret-stdin]
  cloudrec-lite credentials status [--provider alicloud] [--account 123456789|--profile prod] [--format text|json]
  cloudrec-lite credentials delete [--provider alicloud] [--account 123456789|--profile prod]
  cloudrec-lite doctor [--provider alicloud] [--account default] [--rules ./rules/alicloud] [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--credential-source auto|keyring|file|env] [--credential-profile prod] [--env-file .env.local] [--check-provider] [--format text|json]
  cloudrec-lite rules coverage [--rules ./rules/alicloud] [--provider alicloud] [--samples ./samples/alicloud] [--review-ledger ./rules/alicloud/review-ledger.json] [--format table|json]
  cloudrec-lite rules audit [--rules ./rules/alicloud] [--provider alicloud] [--review-ledger ./rules/alicloud/review-ledger.json] [--format table|json]
  cloudrec-lite rules validate [--rules ./rules/alicloud] [--provider alicloud] [--samples ./samples/alicloud] [--format table|json]
  cloudrec-lite rules list [--rules ./rules/alicloud] [--provider alicloud] [--resource-type OSS] [--severity high] [--q bucket] [--limit 100] [--offset 0] [--sort severity|-severity|resource_type|name] [--format table|json|csv]
  cloudrec-lite rules show <rule-id> [--rules ./rules/alicloud] [--provider alicloud] [--format table|json|csv]
  cloudrec-lite dashboard [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--provider alicloud] [--account 123456789] [--region cn-hangzhou] [--format table|json|csv]
  cloudrec-lite risks list [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--provider alicloud] [--account 123456789] [--resource-type OSS] [--region cn-hangzhou] [--severity high] [--status open] [--rule-id alicloud.xxx] [--q bucket] [--limit 100] [--offset 0] [--sort -last_seen_at] [--format table|json|csv]
  cloudrec-lite risks show <finding-id> [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--rules ./rules/alicloud] [--provider alicloud] [--format table|json|csv]
  cloudrec-lite assets list [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--provider alicloud] [--account 123456789] [--resource-type OSS] [--resource-id bucket-name] [--region cn-hangzhou] [--q bucket] [--limit 100] [--offset 0] [--sort -last_seen_at] [--format table|json|csv]
  cloudrec-lite assets show <asset-id> [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--provider alicloud] [--resource-id bucket-name] [--resource-type OSS] [--format table|json|csv]
  cloudrec-lite scans list [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--provider alicloud] [--account 123456789] [--status succeeded] [--q scan] [--limit 100] [--offset 0] [--sort -started_at] [--format table|json|csv]
  cloudrec-lite scans quality [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--rules ./rules/alicloud] [--provider alicloud] [--account 123456789] [--status succeeded] [--limit 100] [--offset 0] [--format table|json|csv]
  cloudrec-lite facets [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--provider alicloud] [--account 123456789] [--resource-type OSS] [--region cn-hangzhou] [--severity high] [--status open] [--q bucket] [--format table|json|csv]
  cloudrec-lite export remediation [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--rules ./rules/alicloud] [--status open] [--severity high] [--format markdown|html|json] [--output remediation.md]
  cloudrec-lite scan [--provider mock] [--account default] [--region cn-hangzhou] [--regions cn-hangzhou,cn-shanghai] [--resource-types OSS,ECS] [--rules ./rules] [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--output text|json] [--fixture input.json] [--credential-source auto|keyring|file|env] [--credential-profile prod] [--env-file .env.local] [--skip-account-validation] [--collector-log-level silent|error|warn|info|debug] [--collector-timeout 60s] [--collector-concurrency 4] [--collector-skip-cache-ttl 24h] [--maxcompute-tenant-id tenant]
  cloudrec-lite serve [--addr 127.0.0.1:8787] [--db <user-config>/cloudrec-lite/cloudrec-lite.db] [--rules ./rules] [--provider alicloud]`)
}
