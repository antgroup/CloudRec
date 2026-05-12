package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/antgroup/CloudRec/lite/internal/core"
	"github.com/antgroup/CloudRec/lite/internal/server"
	"github.com/antgroup/CloudRec/lite/internal/storage"
)

const (
	queryFormatTable = "table"
	queryFormatJSON  = "json"
	queryFormatCSV   = "csv"
)

type queryOptions struct {
	DBPath       string
	RulesDir     string
	Provider     string
	AccountID    string
	ResourceType string
	ResourceID   string
	Region       string
	Severity     string
	Status       string
	RuleID       string
	ScanStatus   string
	Q            string
	Sort         string
	Limit        int
	Offset       int
	Format       string
	ID           string
	Samples      string
	ReviewLedger string
}

type apiResponse struct {
	Body []byte
	Data map[string]any
}

type queryTable struct {
	Headers []string
	Rows    [][]string
}

func runDashboard(args []string) error {
	return runDashboardWithWriter(args, os.Stdout)
}

func runDashboardWithWriter(args []string, w io.Writer) error {
	options, err := parseDashboardQueryOptions(args)
	if err != nil {
		return err
	}
	params := baseQueryParams(options)
	addQueryParam(params, "limit", intQueryParam(options.Limit))

	response, err := callLocalAPI(context.Background(), options, "/api/dashboard", params, true)
	if err != nil {
		return err
	}
	return renderQueryOutput(w, options.Format, response, dashboardTable(response.Data))
}

func runRisks(args []string) error {
	return runRisksWithWriter(args, os.Stdout)
}

func runRisksWithWriter(args []string, w io.Writer) error {
	subcommand, rest := splitQuerySubcommand(args, "list")
	switch subcommand {
	case "list":
		return runRisksListWithWriter(rest, w)
	case "show":
		return runRiskShowWithWriter(rest, w)
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown risks subcommand %q", subcommand)
	}
}

func runRisksListWithWriter(args []string, w io.Writer) error {
	options, err := parseRiskListQueryOptions(args)
	if err != nil {
		return err
	}
	params := baseQueryParams(options)
	addQueryParam(params, "severity", options.Severity)
	addQueryParam(params, "status", options.Status)
	addQueryParam(params, "rule_id", options.RuleID)
	addQueryParam(params, "sort", options.Sort)
	addQueryParam(params, "limit", intQueryParam(options.Limit))
	addQueryParam(params, "offset", intQueryParam(options.Offset))

	response, err := callLocalAPI(context.Background(), options, "/api/findings", params, true)
	if err != nil {
		return err
	}
	return renderQueryOutput(w, options.Format, response, risksTable(response.Data))
}

func runRiskShowWithWriter(args []string, w io.Writer) error {
	id, args := popQueryID(args)
	options, err := parseRiskShowQueryOptions(args, id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(options.ID) == "" {
		return errors.New("risk id is required")
	}
	params := url.Values{}
	addQueryParam(params, "id", options.ID)

	response, err := callLocalAPI(context.Background(), options, "/api/finding", params, true)
	if err != nil {
		return err
	}
	return renderQueryOutput(w, options.Format, response, findingDetailTable(response.Data))
}

func runAssets(args []string) error {
	return runAssetsWithWriter(args, os.Stdout)
}

func runAssetsWithWriter(args []string, w io.Writer) error {
	subcommand, rest := splitQuerySubcommand(args, "list")
	switch subcommand {
	case "list":
		return runAssetsListWithWriter(rest, w)
	case "show":
		return runAssetShowWithWriter(rest, w)
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown assets subcommand %q", subcommand)
	}
}

func runAssetsListWithWriter(args []string, w io.Writer) error {
	options, err := parseAssetListQueryOptions(args)
	if err != nil {
		return err
	}
	params := baseQueryParams(options)
	addQueryParam(params, "resource_id", options.ResourceID)
	addQueryParam(params, "sort", options.Sort)
	addQueryParam(params, "limit", intQueryParam(options.Limit))
	addQueryParam(params, "offset", intQueryParam(options.Offset))

	response, err := callLocalAPI(context.Background(), options, "/api/assets", params, true)
	if err != nil {
		return err
	}
	return renderQueryOutput(w, options.Format, response, assetsTable(response.Data))
}

func runAssetShowWithWriter(args []string, w io.Writer) error {
	id, args := popQueryID(args)
	options, err := parseAssetShowQueryOptions(args, id)
	if err != nil {
		return err
	}
	params := url.Values{}
	addQueryParam(params, "id", options.ID)
	addQueryParam(params, "account_id", options.AccountID)
	addQueryParam(params, "provider", options.Provider)
	addQueryParam(params, "resource_type", options.ResourceType)
	addQueryParam(params, "resource_id", options.ResourceID)
	addQueryParam(params, "limit", intQueryParam(options.Limit))
	if params.Get("id") == "" && params.Get("resource_id") == "" {
		return errors.New("asset id or --resource-id is required")
	}

	response, err := callLocalAPI(context.Background(), options, "/api/asset", params, true)
	if err != nil {
		return err
	}
	return renderQueryOutput(w, options.Format, response, assetDetailTable(response.Data))
}

func runScans(args []string) error {
	return runScansWithWriter(args, os.Stdout)
}

func runScansWithWriter(args []string, w io.Writer) error {
	subcommand, rest := splitQuerySubcommand(args, "list")
	switch subcommand {
	case "list":
		return runScansListWithWriter(rest, w)
	case "quality":
		return runScansQualityWithWriter(rest, w)
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown scans subcommand %q", subcommand)
	}
}

func runScansListWithWriter(args []string, w io.Writer) error {
	options, err := parseScanListQueryOptions(args)
	if err != nil {
		return err
	}
	params := url.Values{}
	addQueryParam(params, "account_id", options.AccountID)
	addQueryParam(params, "provider", options.Provider)
	addQueryParam(params, "status", options.Status)
	addQueryParam(params, "q", options.Q)
	addQueryParam(params, "sort", options.Sort)
	addQueryParam(params, "limit", intQueryParam(options.Limit))
	addQueryParam(params, "offset", intQueryParam(options.Offset))

	response, err := callLocalAPI(context.Background(), options, "/api/scan-runs", params, true)
	if err != nil {
		return err
	}
	return renderQueryOutput(w, options.Format, response, scansTable(response.Data))
}

func runScansQualityWithWriter(args []string, w io.Writer) error {
	options, err := parseScanQualityQueryOptions(args)
	if err != nil {
		return err
	}
	params := url.Values{}
	addQueryParam(params, "account_id", options.AccountID)
	addQueryParam(params, "provider", options.Provider)
	addQueryParam(params, "status", options.Status)
	addQueryParam(params, "q", options.Q)
	addQueryParam(params, "sort", options.Sort)
	addQueryParam(params, "limit", intQueryParam(options.Limit))
	addQueryParam(params, "offset", intQueryParam(options.Offset))

	response, err := callLocalAPI(context.Background(), options, "/api/scan-quality", params, true)
	if err != nil {
		return err
	}
	return renderQueryOutput(w, options.Format, response, scanQualityTable(response.Data))
}

func runFacets(args []string) error {
	return runFacetsWithWriter(args, os.Stdout)
}

func runFacetsWithWriter(args []string, w io.Writer) error {
	options, err := parseFacetsQueryOptions(args)
	if err != nil {
		return err
	}
	params := baseQueryParams(options)
	addQueryParam(params, "severity", options.Severity)
	addQueryParam(params, "status", options.Status)
	addQueryParam(params, "rule_id", options.RuleID)
	addQueryParam(params, "scan_status", options.ScanStatus)
	addQueryParam(params, "limit", intQueryParam(options.Limit))

	response, err := callLocalAPI(context.Background(), options, "/api/facets", params, true)
	if err != nil {
		return err
	}
	return renderQueryOutput(w, options.Format, response, facetsTable(response.Data))
}

func runRulesWithWriter(args []string, w io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("missing rules subcommand")
	}
	switch args[0] {
	case "list":
		return runRulesListWithWriter(args[1:], w)
	case "show":
		return runRuleShowWithWriter(args[1:], w)
	case "coverage":
		return runRulesCoverageWithWriter(args[1:], w)
	case "audit":
		return runRulesAuditWithWriter(args[1:], w)
	case "validate":
		return runRulesValidateWithWriter(args[1:], w)
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown rules subcommand %q", args[0])
	}
}

func runRulesListWithWriter(args []string, w io.Writer) error {
	options, err := parseRulesListQueryOptions(args)
	if err != nil {
		return err
	}
	params := url.Values{}
	addQueryParam(params, "provider", options.Provider)
	addQueryParam(params, "resource_type", options.ResourceType)
	addQueryParam(params, "severity", options.Severity)
	addQueryParam(params, "rule_id", options.RuleID)
	addQueryParam(params, "q", options.Q)
	addQueryParam(params, "sort", options.Sort)
	addQueryParam(params, "limit", intQueryParam(options.Limit))
	addQueryParam(params, "offset", intQueryParam(options.Offset))

	response, err := callLocalAPI(context.Background(), options, "/api/rules", params, false)
	if err != nil {
		return err
	}
	return renderQueryOutput(w, options.Format, response, rulesTable(response.Data))
}

func runRuleShowWithWriter(args []string, w io.Writer) error {
	id, args := popQueryID(args)
	options, err := parseRuleShowQueryOptions(args, id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(options.ID) == "" {
		return errors.New("rule id is required")
	}
	params := url.Values{}
	addQueryParam(params, "provider", options.Provider)
	addQueryParam(params, "rule_id", options.ID)
	addQueryParam(params, "limit", "1")

	response, err := callLocalAPI(context.Background(), options, "/api/rules", params, false)
	if err != nil {
		return err
	}
	rule, ok := firstObject(response.Data, "rules")
	if !ok {
		return fmt.Errorf("rule %q not found", options.ID)
	}
	detail := map[string]any{"rule": rule}
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	response = apiResponse{Body: body, Data: detail}
	return renderQueryOutput(w, options.Format, response, ruleDetailTable(detail))
}

func parseDashboardQueryOptions(args []string) (queryOptions, error) {
	options := defaultQueryOptions()
	fs := newQueryFlagSet("dashboard", &options)
	addStoreFlags(fs, &options)
	addScopeFlags(fs, &options)
	addLimitFlag(fs, &options, 10)
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func parseRiskListQueryOptions(args []string) (queryOptions, error) {
	options := defaultQueryOptions()
	fs := newQueryFlagSet("risks list", &options)
	addStoreFlags(fs, &options)
	addScopeFlags(fs, &options)
	fs.StringVar(&options.Severity, "severity", "", "finding severity")
	fs.StringVar(&options.Status, "status", "", "finding status")
	fs.StringVar(&options.RuleID, "rule-id", "", "rule identifier")
	addListFlags(fs, &options, 100)
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func parseRiskShowQueryOptions(args []string, id string) (queryOptions, error) {
	options := defaultQueryOptions()
	options.ID = id
	fs := newQueryFlagSet("risks show", &options)
	addStoreFlags(fs, &options)
	fs.StringVar(&options.Provider, "provider", options.Provider, "cloud provider")
	fs.StringVar(&options.ID, "id", options.ID, "finding id")
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func parseAssetListQueryOptions(args []string) (queryOptions, error) {
	options := defaultQueryOptions()
	fs := newQueryFlagSet("assets list", &options)
	addStoreFlags(fs, &options)
	addScopeFlags(fs, &options)
	fs.StringVar(&options.ResourceID, "resource-id", "", "cloud resource id")
	addListFlags(fs, &options, 100)
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func parseAssetShowQueryOptions(args []string, id string) (queryOptions, error) {
	options := defaultQueryOptions()
	options.ID = id
	fs := newQueryFlagSet("assets show", &options)
	addStoreFlags(fs, &options)
	addScopeFlags(fs, &options)
	fs.StringVar(&options.ID, "id", options.ID, "asset id")
	fs.StringVar(&options.ResourceID, "resource-id", "", "cloud resource id")
	addLimitFlag(fs, &options, 100)
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func parseScanListQueryOptions(args []string) (queryOptions, error) {
	options := defaultQueryOptions()
	fs := newQueryFlagSet("scans list", &options)
	addStoreFlags(fs, &options)
	addProviderAccountFlags(fs, &options)
	fs.StringVar(&options.Status, "status", "", "scan status")
	fs.StringVar(&options.Q, "q", "", "full-text search")
	addListFlags(fs, &options, 100)
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func parseScanQualityQueryOptions(args []string) (queryOptions, error) {
	options := defaultQueryOptions()
	fs := newQueryFlagSet("scans quality", &options)
	addStoreFlags(fs, &options)
	addProviderAccountFlags(fs, &options)
	fs.StringVar(&options.Status, "status", "", "scan status")
	fs.StringVar(&options.Q, "q", "", "full-text search")
	addListFlags(fs, &options, 100)
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func parseFacetsQueryOptions(args []string) (queryOptions, error) {
	options := defaultQueryOptions()
	fs := newQueryFlagSet("facets", &options)
	addStoreFlags(fs, &options)
	addScopeFlags(fs, &options)
	fs.StringVar(&options.Severity, "severity", "", "finding severity")
	fs.StringVar(&options.Status, "status", "", "finding status")
	fs.StringVar(&options.RuleID, "rule-id", "", "rule identifier")
	fs.StringVar(&options.ScanStatus, "scan-status", "", "scan status")
	addLimitFlag(fs, &options, 1000)
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func parseRulesListQueryOptions(args []string) (queryOptions, error) {
	options := defaultQueryOptions()
	fs := newQueryFlagSet("rules list", &options)
	addRulesFlags(fs, &options)
	fs.StringVar(&options.ResourceType, "resource-type", "", "rule resource type")
	fs.StringVar(&options.Severity, "severity", "", "rule severity")
	fs.StringVar(&options.RuleID, "rule-id", "", "rule identifier")
	addListFlags(fs, &options, 1000)
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func parseRuleShowQueryOptions(args []string, id string) (queryOptions, error) {
	options := defaultQueryOptions()
	options.ID = id
	fs := newQueryFlagSet("rules show", &options)
	addRulesFlags(fs, &options)
	fs.StringVar(&options.ID, "id", options.ID, "rule id")
	addFormatFlag(fs, &options)
	if err := fs.Parse(args); err != nil {
		return queryOptions{}, err
	}
	return normalizeQueryOptions(options)
}

func defaultQueryOptions() queryOptions {
	return queryOptions{
		DBPath:   core.DefaultDBPath(),
		RulesDir: "./rules",
		Limit:    100,
		Format:   queryFormatTable,
	}
}

func newQueryFlagSet(name string, _ *queryOptions) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

func addStoreFlags(fs *flag.FlagSet, options *queryOptions) {
	fs.StringVar(&options.DBPath, "db", options.DBPath, "SQLite database path")
	fs.StringVar(&options.RulesDir, "rules", options.RulesDir, "rule pack directory")
}

func addRulesFlags(fs *flag.FlagSet, options *queryOptions) {
	fs.StringVar(&options.RulesDir, "rules", options.RulesDir, "rule pack directory")
	fs.StringVar(&options.Provider, "provider", options.Provider, "cloud provider")
}

func addScopeFlags(fs *flag.FlagSet, options *queryOptions) {
	addProviderAccountFlags(fs, options)
	fs.StringVar(&options.ResourceType, "resource-type", "", "asset or finding resource type")
	fs.StringVar(&options.Region, "region", "", "cloud region")
	fs.StringVar(&options.Q, "q", "", "full-text search")
}

func addProviderAccountFlags(fs *flag.FlagSet, options *queryOptions) {
	fs.StringVar(&options.AccountID, "account", "", "account id")
	fs.StringVar(&options.AccountID, "account-id", "", "account id")
	fs.StringVar(&options.Provider, "provider", options.Provider, "cloud provider")
}

func addListFlags(fs *flag.FlagSet, options *queryOptions, defaultLimit int) {
	addLimitFlag(fs, options, defaultLimit)
	fs.IntVar(&options.Offset, "offset", 0, "pagination offset")
	fs.StringVar(&options.Sort, "sort", "", "sort key, prefix with - for descending")
}

func addLimitFlag(fs *flag.FlagSet, options *queryOptions, defaultLimit int) {
	options.Limit = defaultLimit
	fs.IntVar(&options.Limit, "limit", defaultLimit, "pagination limit")
}

func addFormatFlag(fs *flag.FlagSet, options *queryOptions) {
	fs.StringVar(&options.Format, "format", queryFormatTable, "output format: table, json, or csv")
}

func normalizeQueryOptions(options queryOptions) (queryOptions, error) {
	options.DBPath = core.NormalizeDBPath(options.DBPath)
	options.RulesDir = strings.TrimSpace(options.RulesDir)
	options.Provider = strings.TrimSpace(options.Provider)
	options.AccountID = strings.TrimSpace(options.AccountID)
	options.ResourceType = strings.TrimSpace(options.ResourceType)
	options.ResourceID = strings.TrimSpace(options.ResourceID)
	options.Region = strings.TrimSpace(options.Region)
	options.Severity = strings.TrimSpace(options.Severity)
	options.Status = strings.TrimSpace(options.Status)
	options.RuleID = strings.TrimSpace(options.RuleID)
	options.ScanStatus = strings.TrimSpace(options.ScanStatus)
	options.Q = strings.TrimSpace(options.Q)
	options.Sort = strings.TrimSpace(options.Sort)
	options.Format = strings.ToLower(strings.TrimSpace(options.Format))
	options.ID = strings.TrimSpace(options.ID)
	if options.Limit <= 0 {
		return queryOptions{}, errors.New("limit must be positive")
	}
	if options.Offset < 0 {
		return queryOptions{}, errors.New("offset must be non-negative")
	}
	if options.RulesDir == "" {
		options.RulesDir = "./rules"
	}
	switch options.Format {
	case queryFormatTable, queryFormatJSON, queryFormatCSV:
		return options, nil
	default:
		return queryOptions{}, fmt.Errorf("unsupported format %q", options.Format)
	}
}

func callLocalAPI(ctx context.Context, options queryOptions, apiPath string, params url.Values, needsStore bool) (apiResponse, error) {
	var store storage.Store
	if needsStore {
		if err := requireQueryDB(options.DBPath); err != nil {
			return apiResponse{}, err
		}
		opened, err := storage.Open(ctx, options.DBPath)
		if err != nil {
			return apiResponse{}, err
		}
		defer opened.Close()
		if err := opened.Init(ctx); err != nil {
			return apiResponse{}, err
		}
		store = opened
	}

	handler := server.NewHandler(
		store,
		server.WithRulesDir(options.RulesDir),
		server.WithProvider(options.Provider),
		server.WithDatabasePath(options.DBPath),
		server.WithVersion(version),
	)
	target := apiPath
	if encoded := params.Encode(); encoded != "" {
		target += "?" + encoded
	}
	req := httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	body := recorder.Body.Bytes()
	if recorder.Code < 200 || recorder.Code >= 300 {
		return apiResponse{}, fmt.Errorf("%s failed: %s", apiPath, apiErrorMessage(body, recorder.Code))
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return apiResponse{}, fmt.Errorf("decode %s response: %w", apiPath, err)
	}
	return apiResponse{Body: body, Data: data}, nil
}

func requireQueryDB(dbPath string) error {
	if strings.TrimSpace(dbPath) == "" {
		return errors.New("database path is required")
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("database %q does not exist; run scan first or pass --db", dbPath)
		}
		return fmt.Errorf("stat database %q: %w", dbPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("database path %q is a directory", dbPath)
	}
	return nil
}

func apiErrorMessage(body []byte, status int) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err == nil {
		if message := stringField(payload, "error"); message != "" {
			return message
		}
	}
	return fmt.Sprintf("HTTP %d", status)
}

func renderQueryOutput(w io.Writer, format string, response apiResponse, table queryTable) error {
	switch format {
	case queryFormatJSON:
		return writePrettyJSON(w, response.Body)
	case queryFormatCSV:
		return renderCSV(w, table)
	case queryFormatTable:
		return renderTable(w, table)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writePrettyJSON(w io.Writer, body []byte) error {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		return err
	}
	pretty.WriteByte('\n')
	_, err := w.Write(pretty.Bytes())
	return err
}

func renderTable(w io.Writer, table queryTable) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(table.Headers) > 0 {
		fmt.Fprintln(tw, strings.Join(table.Headers, "\t"))
	}
	for _, row := range table.Rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

func renderCSV(w io.Writer, table queryTable) error {
	cw := csv.NewWriter(w)
	if len(table.Headers) > 0 {
		if err := cw.Write(table.Headers); err != nil {
			return err
		}
	}
	for _, row := range table.Rows {
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func dashboardTable(data map[string]any) queryTable {
	latestScanID := stringField(objectField(data, "latest_scan_run"), "id")
	if latestScanID == "" {
		latestScanID = stringField(objectField(objectField(data, "summary"), "latest_scan_run"), "id")
	}
	if latestScanID == "" {
		latestScanID = "none"
	}
	return queryTable{
		Headers: []string{"Metric", "Value"},
		Rows: [][]string{
			{"Assets", numberString(data, "asset_count", "summary.asset_count")},
			{"Open Risks", numberString(data, "open_finding_count", "summary.open_finding_count")},
			{"All Risks", numberString(data, "finding_count", "summary.finding_count")},
			{"Critical Risks", numberString(data, "critical_finding_count")},
			{"High Risks", numberString(data, "high_finding_count")},
			{"Relationships", numberString(data, "relationship_count", "summary.relationship_count")},
			{"Rules", numberString(data, "rule_count")},
			{"Accounts", numberString(data, "account_count")},
			{"Latest Scan", latestScanID},
		},
	}
}

func risksTable(data map[string]any) queryTable {
	rows := [][]string{}
	for _, finding := range sliceField(data, "findings") {
		row := objectValue(finding)
		rows = append(rows, []string{
			stringField(row, "id"),
			stringField(row, "severity"),
			stringField(row, "status"),
			stringField(row, "rule_id"),
			stringField(row, "title"),
			stringField(row, "asset_id"),
		})
	}
	return queryTable{
		Headers: []string{"id", "severity", "status", "rule_id", "title", "asset_id"},
		Rows:    rows,
	}
}

func findingDetailTable(data map[string]any) queryTable {
	finding := objectField(data, "finding")
	return queryTable{
		Headers: []string{"Field", "Value"},
		Rows: [][]string{
			{"id", stringField(finding, "id")},
			{"severity", stringField(finding, "severity")},
			{"status", stringField(finding, "status")},
			{"rule_id", stringField(finding, "rule_id")},
			{"title", stringField(finding, "title")},
			{"asset_id", stringField(finding, "asset_id")},
			{"asset_resource_id", stringField(finding, "asset_resource_id")},
			{"remediation", stringField(finding, "remediation")},
		},
	}
}

func assetsTable(data map[string]any) queryTable {
	rows := [][]string{}
	for _, asset := range sliceField(data, "assets") {
		row := objectValue(asset)
		rows = append(rows, []string{
			stringField(row, "id"),
			stringField(row, "resource_type"),
			stringField(row, "name"),
			stringField(row, "region"),
			stringField(row, "resource_id"),
		})
	}
	return queryTable{
		Headers: []string{"id", "resource_type", "name", "region", "resource_id"},
		Rows:    rows,
	}
}

func assetDetailTable(data map[string]any) queryTable {
	asset := objectField(data, "asset")
	return queryTable{
		Headers: []string{"Field", "Value"},
		Rows: [][]string{
			{"id", stringField(asset, "id")},
			{"resource_type", stringField(asset, "resource_type")},
			{"name", stringField(asset, "name")},
			{"region", stringField(asset, "region")},
			{"resource_id", stringField(asset, "resource_id")},
			{"open_finding_count", numberString(asset, "open_finding_count")},
			{"relationships", strconv.Itoa(len(sliceField(data, "relationships")))},
			{"findings", strconv.Itoa(len(sliceField(data, "findings")))},
		},
	}
}

func rulesTable(data map[string]any) queryTable {
	rows := [][]string{}
	for _, rule := range sliceField(data, "rules") {
		row := objectValue(rule)
		rows = append(rows, []string{
			stringField(row, "id"),
			stringField(row, "severity"),
			stringField(row, "provider"),
			stringField(row, "resource_type"),
			boolString(row, "disabled"),
			stringField(row, "name"),
		})
	}
	return queryTable{
		Headers: []string{"id", "severity", "provider", "resource_type", "disabled", "name"},
		Rows:    rows,
	}
}

func ruleDetailTable(data map[string]any) queryTable {
	rule := objectField(data, "rule")
	return queryTable{
		Headers: []string{"Field", "Value"},
		Rows: [][]string{
			{"id", stringField(rule, "id")},
			{"name", stringField(rule, "name")},
			{"severity", stringField(rule, "severity")},
			{"provider", stringField(rule, "provider")},
			{"resource_type", stringField(rule, "resource_type")},
			{"disabled", boolString(rule, "disabled")},
			{"remediation", stringField(rule, "remediation")},
			{"link", stringField(rule, "link")},
		},
	}
}

func scansTable(data map[string]any) queryTable {
	rows := [][]string{}
	for _, run := range sliceField(data, "scan_runs") {
		row := objectValue(run)
		summary := objectField(row, "summary")
		rows = append(rows, []string{
			stringField(row, "id"),
			stringField(row, "status"),
			stringField(row, "provider"),
			stringField(row, "account_id"),
			stringField(row, "started_at"),
			numberString(summary, "assets"),
			numberString(summary, "findings"),
		})
	}
	return queryTable{
		Headers: []string{"id", "status", "provider", "account_id", "started_at", "assets", "findings"},
		Rows:    rows,
	}
}

func scanQualityTable(data map[string]any) queryTable {
	summary := objectField(data, "summary")
	return queryTable{
		Headers: []string{"Metric", "Value"},
		Rows: [][]string{
			{"total_runs", numberString(summary, "total_runs")},
			{"succeeded_runs", numberString(summary, "succeeded_runs")},
			{"failed_runs", numberString(summary, "failed_runs")},
			{"assets_collected", numberString(summary, "assets_collected")},
			{"findings", numberString(summary, "findings")},
			{"rules", numberString(summary, "rules")},
			{"evaluated_rules", numberString(summary, "evaluated_rules")},
			{"collection_failures", numberString(summary, "collection_failures")},
			{"rule_quality_status", stringField(summary, "rule_quality_status")},
		},
	}
}

func facetsTable(data map[string]any) queryTable {
	rows := [][]string{}
	for _, key := range []string{"accounts", "providers", "regions", "resource_types", "asset_types", "severities", "statuses", "rules", "scan_statuses"} {
		for _, item := range sliceField(data, key) {
			value := objectValue(item)
			rows = append(rows, []string{key, stringField(value, "value"), numberString(value, "count")})
		}
	}
	return queryTable{
		Headers: []string{"facet", "value", "count"},
		Rows:    rows,
	}
}

func baseQueryParams(options queryOptions) url.Values {
	params := url.Values{}
	addQueryParam(params, "account_id", options.AccountID)
	addQueryParam(params, "provider", options.Provider)
	addQueryParam(params, "resource_type", options.ResourceType)
	addQueryParam(params, "region", options.Region)
	addQueryParam(params, "q", options.Q)
	return params
}

func addQueryParam(params url.Values, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	params.Set(key, strings.TrimSpace(value))
}

func intQueryParam(value int) string {
	if value <= 0 {
		return ""
	}
	return strconv.Itoa(value)
}

func splitQuerySubcommand(args []string, defaultSubcommand string) (string, []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return defaultSubcommand, args
	}
	return args[0], args[1:]
}

func popQueryID(args []string) (string, []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", args
	}
	return args[0], args[1:]
}

func firstObject(data map[string]any, key string) (map[string]any, bool) {
	items := sliceField(data, key)
	if len(items) == 0 {
		return nil, false
	}
	return objectValue(items[0]), true
}

func sliceField(data map[string]any, key string) []any {
	value, ok := data[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []any:
		return typed
	default:
		return nil
	}
}

func objectField(data map[string]any, key string) map[string]any {
	value, ok := data[key]
	if !ok || value == nil {
		return map[string]any{}
	}
	return objectValue(value)
}

func objectValue(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{}
}

func stringField(data map[string]any, key string) string {
	value, ok := data[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return fmt.Sprint(typed)
	}
}

func boolString(data map[string]any, key string) string {
	value, ok := data[key].(bool)
	if !ok {
		return "false"
	}
	return strconv.FormatBool(value)
}

func numberString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if strings.Contains(key, ".") {
			parts := strings.Split(key, ".")
			current := data
			for i, part := range parts {
				if i == len(parts)-1 {
					if out := stringField(current, part); out != "" {
						return out
					}
					break
				}
				current = objectField(current, part)
			}
			continue
		}
		if out := stringField(data, key); out != "" {
			return out
		}
	}
	return "0"
}
