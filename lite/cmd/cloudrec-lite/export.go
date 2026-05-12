package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/antgroup/CloudRec/lite/internal/core"
	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/internal/report"
	"github.com/antgroup/CloudRec/lite/internal/rule"
	"github.com/antgroup/CloudRec/lite/internal/storage"
)

func runExport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing export subcommand")
	}
	switch args[0] {
	case "remediation":
		return runExportRemediation(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown export subcommand %q", args[0])
	}
}

func runExportRemediation(args []string) error {
	return runExportRemediationWithWriter(args, os.Stdout)
}

func runExportRemediationWithWriter(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("export remediation", flag.ContinueOnError)
	db := fs.String("db", core.DefaultDBPath(), "SQLite database path")
	rules := fs.String("rules", "", "optional rule pack directory used to hydrate missing remediation text")
	account := fs.String("account", "", "account id filter")
	provider := fs.String("provider", "", "provider filter")
	resourceType := fs.String("resource-type", "", "resource type filter")
	region := fs.String("region", "", "region filter")
	severity := fs.String("severity", "", "severity filter")
	status := fs.String("status", "open", "finding status filter")
	ruleID := fs.String("rule", "", "rule id filter")
	query := fs.String("q", "", "full-text search filter")
	sort := fs.String("sort", "-severity", "sort field, such as -severity or -last_seen_at")
	limit := fs.Int("limit", 1000, "maximum findings to export")
	format := fs.String("format", report.FormatMarkdown, "output format: markdown, html, or json")
	output := fs.String("output", "", "optional output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *limit <= 0 || *limit > 10000 {
		return fmt.Errorf("limit must be between 1 and 10000")
	}
	dbPath := core.NormalizeDBPath(*db)
	if err := requireExistingDB(dbPath); err != nil {
		return err
	}

	ctx := context.Background()
	store, err := storage.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Init(ctx); err != nil {
		return err
	}
	findings, err := store.ListFindingViews(ctx, storage.FindingFilter{
		AccountID:    *account,
		Provider:     *provider,
		ResourceType: *resourceType,
		Region:       *region,
		RuleID:       *ruleID,
		Severity:     *severity,
		Status:       *status,
		Q:            *query,
		Sort:         *sort,
		Limit:        *limit,
	})
	if err != nil {
		return err
	}
	findings.Findings = hydrateRemediationFromRules(findings.Findings, *rules)

	writer := w
	var file *os.File
	if strings.TrimSpace(*output) != "" {
		file, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("open export output %q: %w", *output, err)
		}
		defer file.Close()
		writer = file
	}
	return report.RenderRemediationExport(writer, findings.Findings, report.RemediationExportOptions{Format: *format})
}

func hydrateRemediationFromRules(findings []model.FindingView, rulesDir string) []model.FindingView {
	rulesDir = strings.TrimSpace(rulesDir)
	if rulesDir == "" || len(findings) == 0 {
		return findings
	}
	packs, err := rule.LoadDirWithOptions(rulesDir, rule.LoadDirOptions{IncludeDisabled: true})
	if err != nil {
		return findings
	}
	index := map[string]string{}
	for _, pack := range packs {
		id := strings.TrimSpace(pack.Metadata.ID)
		remediation := strings.TrimSpace(pack.Remediation)
		if remediation == "" {
			remediation = strings.TrimSpace(pack.Metadata.Advice)
		}
		if id == "" || remediation == "" {
			continue
		}
		index[id] = remediation
		index[strings.ToLower(id)] = remediation
	}
	for i := range findings {
		if strings.TrimSpace(findings[i].Remediation) != "" {
			continue
		}
		if remediation := index[findings[i].RuleID]; remediation != "" {
			findings[i].Remediation = remediation
			continue
		}
		if remediation := index[strings.ToLower(strings.TrimSpace(findings[i].RuleID))]; remediation != "" {
			findings[i].Remediation = remediation
		}
	}
	return findings
}

func requireExistingDB(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("database path is required")
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("database %q does not exist; run a scan first or pass --db to an existing SQLite database", path)
	}
	if err != nil {
		return fmt.Errorf("stat database %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("database %q is a directory", path)
	}
	return nil
}
