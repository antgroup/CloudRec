package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/bundle"
	"github.com/antgroup/CloudRec/lite/internal/core"
	liteprovider "github.com/antgroup/CloudRec/lite/internal/provider"
	"github.com/antgroup/CloudRec/lite/internal/rule"
	"github.com/antgroup/CloudRec/lite/internal/server"
	"github.com/antgroup/CloudRec/lite/providers/alicloud"
)

const (
	doctorFormatText = "text"
	doctorFormatJSON = "json"

	doctorStatusPass = "pass"
	doctorStatusWarn = "warn"
	doctorStatusFail = "fail"
	doctorStatusSkip = "skip"

	doctorTempSpaceProbeBytes = 32 * 1024 * 1024
)

var errDoctorFailed = errors.New("doctor found failed checks")

type doctorReport struct {
	Provider          string        `json:"provider"`
	Account           string        `json:"account"`
	Region            string        `json:"region,omitempty"`
	RulesDir          string        `json:"rules_dir"`
	DBPath            string        `json:"db_path"`
	EnvFile           string        `json:"env_file,omitempty"`
	CredentialSource  string        `json:"credential_source,omitempty"`
	CredentialProfile string        `json:"credential_profile,omitempty"`
	Checks            []doctorCheck `json:"checks"`
	Summary           doctorSummary `json:"summary"`
}

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

type doctorSummary struct {
	Passed  int `json:"passed"`
	Warned  int `json:"warned"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

func runDoctor(args []string) error {
	return runDoctorWithWriter(args, os.Stdout)
}

func runDoctorWithWriter(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	providerName := fs.String("provider", "alicloud", "cloud provider to diagnose")
	account := fs.String("account", "default", "account identifier or profile")
	region := fs.String("region", "", "default cloud region")
	rules := fs.String("rules", "", "optional rule pack directory; defaults to built-in provider rules")
	db := fs.String("db", core.DefaultDBPath(), "SQLite database path")
	envFile := fs.String("env-file", "", "optional plaintext env file fallback for credentials; missing files are reported as warnings")
	credentialSource := fs.String("credential-source", alicloud.CredentialSourceAuto, "credential source: auto, keyring, file, or env")
	credentialProfile := fs.String("credential-profile", "", "system credential store profile; defaults to --account")
	format := fs.String("format", doctorFormatText, "output format: text or json")
	checkProvider := fs.Bool("check-provider", false, "perform live provider account validation")
	skipAccountValidation := fs.Bool("skip-account-validation", false, "skip live Alibaba Cloud account validation when --check-provider is enabled")
	timeout := fs.Duration("timeout", 30*time.Second, "live provider validation timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	envLoadErr := loadEnvFile(*envFile)
	report := buildDoctorReport(doctorOptions{
		Provider:              *providerName,
		Account:               *account,
		Region:                *region,
		RulesDir:              *rules,
		DBPath:                *db,
		EnvFile:               *envFile,
		CredentialSource:      *credentialSource,
		CredentialProfile:     *credentialProfile,
		CheckProvider:         *checkProvider,
		SkipAccountValidation: *skipAccountValidation,
		Timeout:               *timeout,
		EnvLoadErr:            envLoadErr,
	})

	if err := renderDoctorReport(w, report, *format); err != nil {
		return err
	}
	if report.Summary.Failed > 0 {
		return errDoctorFailed
	}
	return nil
}

type doctorOptions struct {
	Provider              string
	Account               string
	Region                string
	RulesDir              string
	DBPath                string
	EnvFile               string
	CredentialSource      string
	CredentialProfile     string
	CheckProvider         bool
	SkipAccountValidation bool
	Timeout               time.Duration
	EnvLoadErr            error
}

func buildDoctorReport(options doctorOptions) doctorReport {
	options.Provider = strings.ToLower(strings.TrimSpace(options.Provider))
	options.Account = strings.TrimSpace(options.Account)
	options.Region = strings.TrimSpace(options.Region)
	options.RulesDir = strings.TrimSpace(options.RulesDir)
	options.DBPath = core.NormalizeDBPath(options.DBPath)
	options.EnvFile = strings.TrimSpace(options.EnvFile)
	options.CredentialSource = alicloud.NormalizeCredentialSource(options.CredentialSource)
	options.CredentialProfile = strings.TrimSpace(options.CredentialProfile)
	if options.Provider == "" {
		options.Provider = "alicloud"
	}
	if options.Account == "" {
		options.Account = "default"
	}
	report := doctorReport{
		Provider:          options.Provider,
		Account:           options.Account,
		Region:            options.Region,
		RulesDir:          options.RulesDir,
		DBPath:            options.DBPath,
		EnvFile:           options.EnvFile,
		CredentialSource:  options.CredentialSource,
		CredentialProfile: options.CredentialProfile,
	}
	report.Checks = append(report.Checks,
		doctorEnvFileCheck(options.EnvFile, options.EnvLoadErr),
		doctorRulesCheck(options.RulesDir),
		doctorReviewLedgerCheck(options.RulesDir),
		doctorSamplesCheck(options.RulesDir, options.Provider),
		doctorDBPathCheck(options.DBPath),
		doctorTempSpaceCheck(),
		doctorCredentialCheck(options),
		doctorProviderCheck(options),
	)
	report.Summary = summarizeDoctorChecks(report.Checks)
	return report
}

func doctorEnvFileCheck(path string, loadErr error) doctorCheck {
	path = strings.TrimSpace(path)
	if path == "" {
		return doctorCheck{Name: "env_file", Status: doctorStatusSkip, Message: "no env file configured"}
	}
	if loadErr != nil {
		return doctorCheck{
			Name:    "env_file",
			Status:  doctorStatusFail,
			Message: sanitizeDoctorMessage(loadErr.Error()),
			Hint:    "Fix the env file syntax or run with --env-file pointing to a readable local file.",
		}
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return doctorCheck{
			Name:    "env_file",
			Status:  doctorStatusWarn,
			Message: fmt.Sprintf("%s was not found; this is okay when using the system credential store or explicit environment variables", path),
			Hint:    "Prefer cloudrec-lite credentials store; use .env.local only for local development fallback.",
		}
	}
	if err != nil {
		return doctorCheck{Name: "env_file", Status: doctorStatusFail, Message: sanitizeDoctorMessage(err.Error())}
	}
	if info.IsDir() {
		return doctorCheck{Name: "env_file", Status: doctorStatusFail, Message: fmt.Sprintf("%s is a directory", path)}
	}
	return doctorCheck{Name: "env_file", Status: doctorStatusPass, Message: fmt.Sprintf("%s loaded without printing credential values", path)}
}

func doctorRulesCheck(rulesDir string) doctorCheck {
	resolvedRulesDir, err := bundle.ResolveRulesDir(rulesDir, "alicloud", true)
	if err != nil {
		return doctorCheck{
			Name:    "rules",
			Status:  doctorStatusFail,
			Message: err.Error(),
			Hint:    "Omit --rules to use the built-in rule pack, or point --rules to a valid custom rule pack directory.",
		}
	}
	if err := server.ValidateRulesDir(resolvedRulesDir); err != nil {
		return doctorCheck{Name: "rules", Status: doctorStatusFail, Message: err.Error()}
	}
	packs, err := rule.LoadDirWithOptions(resolvedRulesDir, rule.LoadDirOptions{IncludeDisabled: true})
	if err != nil {
		return doctorCheck{Name: "rules", Status: doctorStatusFail, Message: "rule packs failed to load: " + err.Error()}
	}
	if len(packs) == 0 {
		return doctorCheck{Name: "rules", Status: doctorStatusWarn, Message: "rules directory is valid but contains no rule packs"}
	}
	return doctorCheck{Name: "rules", Status: doctorStatusPass, Message: fmt.Sprintf("%d rule packs are loadable", len(packs))}
}

func doctorReviewLedgerCheck(rulesDir string) doctorCheck {
	resolvedRulesDir, err := bundle.ResolveRulesDir(rulesDir, "alicloud", true)
	if err != nil {
		return doctorCheck{Name: "review_ledger", Status: doctorStatusFail, Message: err.Error()}
	}
	path := filepath.Join(strings.TrimSpace(resolvedRulesDir), "review-ledger.json")
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return doctorCheck{
			Name:    "review_ledger",
			Status:  doctorStatusWarn,
			Message: fmt.Sprintf("%s was not found", path),
			Hint:    "Run rules audit with --review-ledger or create a review-ledger.json before marking rules as officially reviewed.",
		}
	}
	if err != nil {
		return doctorCheck{Name: "review_ledger", Status: doctorStatusFail, Message: sanitizeDoctorMessage(err.Error())}
	}
	if info.IsDir() {
		return doctorCheck{Name: "review_ledger", Status: doctorStatusFail, Message: fmt.Sprintf("%s is a directory", path)}
	}
	file, err := os.Open(path)
	if err != nil {
		return doctorCheck{Name: "review_ledger", Status: doctorStatusFail, Message: sanitizeDoctorMessage(err.Error())}
	}
	defer file.Close()
	var ledger struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.NewDecoder(file).Decode(&ledger); err != nil {
		return doctorCheck{Name: "review_ledger", Status: doctorStatusFail, Message: "review ledger is not valid JSON: " + err.Error()}
	}
	if len(ledger.Rules) == 0 {
		return doctorCheck{Name: "review_ledger", Status: doctorStatusWarn, Message: fmt.Sprintf("%s has no rule review records", path)}
	}
	return doctorCheck{Name: "review_ledger", Status: doctorStatusPass, Message: fmt.Sprintf("%d review records loaded from %s", len(ledger.Rules), path)}
}

func doctorSamplesCheck(rulesDir string, provider string) doctorCheck {
	resolvedRulesDir, err := bundle.ResolveRulesDir(rulesDir, provider, true)
	if err != nil {
		return doctorCheck{Name: "samples", Status: doctorStatusFail, Message: err.Error()}
	}
	samplesDir, err := resolveDoctorSamplesDir(resolvedRulesDir, provider)
	if err != nil {
		return doctorCheck{
			Name:    "samples",
			Status:  doctorStatusWarn,
			Message: err.Error(),
			Hint:    "Add sanitized samples under ./samples/<provider> or run rules validate with --samples to verify collector fields.",
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := rule.AnalyzeValidation(ctx, rule.ValidationOptions{
		RulesDir:   resolvedRulesDir,
		Provider:   provider,
		SamplesDir: samplesDir,
	})
	if err != nil {
		return doctorCheck{Name: "samples", Status: doctorStatusFail, Message: "sample validation failed: " + err.Error()}
	}
	if report.Totals.MissingSampleRefs > 0 {
		return doctorCheck{
			Name:    "samples",
			Status:  doctorStatusWarn,
			Message: fmt.Sprintf("%s loaded, but %d rule field refs are missing from samples", samplesDir, report.Totals.MissingSampleRefs),
			Hint:    "Refresh sanitized sample pack from collector/native-adapter output before trusting coverage as field-verified.",
		}
	}
	return doctorCheck{Name: "samples", Status: doctorStatusPass, Message: fmt.Sprintf("%s verifies %d rule(s)", samplesDir, report.Totals.RealFieldVerified)}
}

func resolveDoctorSamplesDir(rulesDir string, provider string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "alicloud"
	}
	candidates := []string{
		filepath.Join(filepath.Dir(strings.TrimSpace(rulesDir)), "..", "samples", provider),
		filepath.Join(filepath.Dir(strings.TrimSpace(rulesDir)), "samples", provider),
		filepath.Join("samples", provider),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
	}
	return bundle.ResolveSamplesDir("", provider)
}

func doctorDBPathCheck(dbPath string) doctorCheck {
	if strings.TrimSpace(dbPath) == "" {
		return doctorCheck{Name: "database", Status: doctorStatusFail, Message: "database path is empty"}
	}
	if info, err := os.Stat(dbPath); err == nil {
		if info.IsDir() {
			return doctorCheck{Name: "database", Status: doctorStatusFail, Message: fmt.Sprintf("%s is a directory", dbPath)}
		}
		return doctorCheck{Name: "database", Status: doctorStatusPass, Message: fmt.Sprintf("%s exists and is a file", dbPath)}
	} else if !errors.Is(err, os.ErrNotExist) {
		return doctorCheck{Name: "database", Status: doctorStatusFail, Message: sanitizeDoctorMessage(err.Error())}
	}

	parent := filepath.Dir(dbPath)
	if parent == "" {
		parent = "."
	}
	if _, err := os.Stat(parent); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return doctorCheck{Name: "database", Status: doctorStatusFail, Message: fmt.Sprintf("database parent %s cannot be created: %v", parent, err)}
		}
	}
	info, err := os.Stat(parent)
	if err != nil {
		return doctorCheck{Name: "database", Status: doctorStatusFail, Message: fmt.Sprintf("database parent %s is not accessible: %v", parent, err)}
	}
	if !info.IsDir() {
		return doctorCheck{Name: "database", Status: doctorStatusFail, Message: fmt.Sprintf("database parent %s is not a directory", parent)}
	}
	file, err := os.CreateTemp(parent, ".cloudrec-lite-doctor-*")
	if err != nil {
		return doctorCheck{Name: "database", Status: doctorStatusFail, Message: fmt.Sprintf("database parent %s is not writable: %v", parent, err)}
	}
	name := file.Name()
	_ = file.Close()
	_ = os.Remove(name)
	return doctorCheck{Name: "database", Status: doctorStatusPass, Message: fmt.Sprintf("%s can be created by scan or serve", dbPath)}
}

func doctorTempSpaceCheck() doctorCheck {
	tmpDir := strings.TrimSpace(os.Getenv("GOTMPDIR"))
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	file, err := os.CreateTemp(tmpDir, ".cloudrec-lite-temp-space-*")
	if err != nil {
		return doctorCheck{
			Name:    "temp_space",
			Status:  doctorStatusFail,
			Message: fmt.Sprintf("cannot create a probe file in %s: %v", tmpDir, err),
			Hint:    "Free disk space or set GOTMPDIR to a writable volume before running tests or release builds.",
		}
	}
	name := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(name)
	}()
	chunk := make([]byte, 1024*1024)
	written := 0
	for written < doctorTempSpaceProbeBytes {
		n, err := file.Write(chunk)
		written += n
		if err != nil {
			return doctorCheck{
				Name:    "temp_space",
				Status:  doctorStatusFail,
				Message: fmt.Sprintf("temporary directory %s could not allocate %d MiB: %v", tmpDir, doctorTempSpaceProbeBytes/(1024*1024), err),
				Hint:    "Clean build caches or set GOTMPDIR to a larger local disk before running go test or release builds.",
			}
		}
	}
	return doctorCheck{Name: "temp_space", Status: doctorStatusPass, Message: fmt.Sprintf("%s can allocate a %d MiB build probe", tmpDir, doctorTempSpaceProbeBytes/(1024*1024))}
}

func doctorCredentialCheck(options doctorOptions) doctorCheck {
	switch options.Provider {
	case "mock":
		return doctorCheck{Name: "credentials", Status: doctorStatusSkip, Message: "mock provider does not require cloud credentials"}
	case alicloud.ProviderName:
		credentials, err := alicloud.ResolveCredentials(doctorProviderAccount(options))
		if err != nil {
			return doctorCheck{
				Name:    "credentials",
				Status:  doctorStatusFail,
				Message: sanitizeDoctorMessage(err.Error()),
				Hint:    "Run cloudrec-lite credentials store --provider alicloud --account <account-id>, or use --credential-source env for one-shot environment variables.",
			}
		}
		parts := []string{
			fmt.Sprintf("source %s", alicloud.CredentialSource(doctorProviderAccount(options))),
			fmt.Sprintf("profile %s", alicloud.CredentialProfile(doctorProviderAccount(options))),
			"access key id present",
			"access key secret present",
		}
		if strings.TrimSpace(credentials.SecurityToken) != "" {
			parts = append(parts, "security token present")
		}
		if strings.TrimSpace(credentials.Region) != "" {
			parts = append(parts, "region configured")
		}
		return doctorCheck{Name: "credentials", Status: doctorStatusPass, Message: strings.Join(parts, ", ")}
	default:
		return doctorCheck{Name: "credentials", Status: doctorStatusWarn, Message: fmt.Sprintf("provider %s has no doctor credential checks yet", options.Provider)}
	}
}

func doctorProviderCheck(options doctorOptions) doctorCheck {
	if !options.CheckProvider {
		return doctorCheck{
			Name:    "provider",
			Status:  doctorStatusSkip,
			Message: "live provider validation was not requested",
			Hint:    "Run with --check-provider when you want doctor to call the provider validation API.",
		}
	}
	if options.Provider == "mock" {
		return doctorCheck{Name: "provider", Status: doctorStatusPass, Message: "mock provider is available locally"}
	}
	if options.Provider != alicloud.ProviderName {
		return doctorCheck{Name: "provider", Status: doctorStatusWarn, Message: fmt.Sprintf("provider %s has no live doctor validation yet", options.Provider)}
	}
	if options.SkipAccountValidation {
		return doctorCheck{Name: "provider", Status: doctorStatusSkip, Message: "live Alibaba Cloud account validation skipped by flag"}
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := alicloud.New().ValidateAccount(ctx, doctorProviderAccount(options)); err != nil {
		return doctorCheck{
			Name:    "provider",
			Status:  doctorStatusFail,
			Message: sanitizeDoctorMessage(err.Error()),
			Hint:    "Check network access, RAM permissions, account id, and whether STS validation is supported by the selected collector path.",
		}
	}
	return doctorCheck{Name: "provider", Status: doctorStatusPass, Message: "Alibaba Cloud account validation succeeded"}
}

func doctorProviderAccount(options doctorOptions) liteprovider.Account {
	config := map[string]string{}
	if options.Region != "" {
		config["region"] = options.Region
	}
	if options.CredentialSource != "" {
		config[alicloud.ConfigCredentialSource] = options.CredentialSource
	}
	if options.CredentialProfile != "" {
		config[alicloud.ConfigCredentialProfile] = options.CredentialProfile
	}
	if options.SkipAccountValidation {
		config["skip_account_validation"] = "true"
	}
	return liteprovider.Account{
		Provider:      options.Provider,
		AccountID:     options.Account,
		DefaultRegion: options.Region,
		Config:        config,
	}
}

func summarizeDoctorChecks(checks []doctorCheck) doctorSummary {
	var summary doctorSummary
	for _, check := range checks {
		switch check.Status {
		case doctorStatusPass:
			summary.Passed++
		case doctorStatusWarn:
			summary.Warned++
		case doctorStatusFail:
			summary.Failed++
		case doctorStatusSkip:
			summary.Skipped++
		}
	}
	return summary
}

func renderDoctorReport(w io.Writer, report doctorReport, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", doctorFormatText:
		fmt.Fprintf(w, "CloudRec Lite doctor provider=%s account=%s\n\n", report.Provider, report.Account)
		fmt.Fprintf(w, "%-16s %-6s %s\n", "Check", "Status", "Message")
		for _, check := range report.Checks {
			fmt.Fprintf(w, "%-16s %-6s %s\n", check.Name, check.Status, check.Message)
			if strings.TrimSpace(check.Hint) != "" {
				fmt.Fprintf(w, "%-16s %-6s %s\n", "", "", "hint: "+check.Hint)
			}
		}
		fmt.Fprintf(w, "\nSummary: pass=%d warn=%d fail=%d skip=%d\n", report.Summary.Passed, report.Summary.Warned, report.Summary.Failed, report.Summary.Skipped)
		return nil
	case doctorFormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	default:
		return fmt.Errorf("unsupported doctor format %q", format)
	}
}

func sanitizeDoctorMessage(message string) string {
	output := message
	for key := range allowedEnvFileKeys {
		value := strings.TrimSpace(os.Getenv(key))
		if value == "" {
			continue
		}
		output = strings.ReplaceAll(output, value, "[redacted]")
	}
	return output
}
