package rule

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

type OPAEngine struct{}

func NewOPAEngine() OPAEngine {
	return OPAEngine{}
}

func (e OPAEngine) Evaluate(ctx context.Context, pack RulePack, asset any) ([]FindingResult, error) {
	input, err := normalizeAssetInput(asset)
	if err != nil {
		return nil, err
	}

	query, err := queryForPack(pack)
	if err != nil {
		return nil, err
	}

	options := []func(*rego.Rego){
		rego.Query(query),
		rego.Module(pack.PolicyPath, pack.Policy),
	}
	if len(pack.Data) > 0 {
		options = append(options, rego.Store(inmem.NewFromObject(pack.Data)))
	}

	prepared, err := rego.New(options...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare rego query %q: %w", query, err)
	}

	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("eval rego query %q: %w", query, err)
	}
	if len(results) == 0 {
		return nil, nil
	}

	var findings []FindingResult
	for _, result := range results {
		for _, expression := range result.Expressions {
			resultFindings, err := findingsFromValue(pack, expression.Value)
			if err != nil {
				return nil, err
			}
			findings = append(findings, resultFindings...)
		}
	}
	return findings, nil
}

var regoPackagePattern = regexp.MustCompile(`(?m)^\s*package\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*$`)

func queryForPack(pack RulePack) (string, error) {
	if strings.TrimSpace(pack.Metadata.Query) != "" {
		return pack.Metadata.Query, nil
	}

	entrypoint := strings.TrimSpace(pack.Metadata.EntryPoint)
	if strings.HasPrefix(entrypoint, "data.") {
		return entrypoint, nil
	}
	if entrypoint == "" {
		entrypoint = defaultEntryPointForPolicy(pack.Policy)
	}

	match := regoPackagePattern.FindStringSubmatch(pack.Policy)
	if len(match) != 2 {
		return "", fmt.Errorf("rule %s has no rego package and no metadata query", pack.Metadata.ID)
	}
	return "data." + match[1] + "." + entrypoint, nil
}

func defaultEntryPointForPolicy(policy string) string {
	if regoRuleDeclared(policy, "findings") {
		return "findings"
	}
	if regoRuleDeclared(policy, "risk") {
		return "risk"
	}
	return "findings"
}

func regoRuleDeclared(policy string, name string) bool {
	pattern := regexp.MustCompile(`(?m)^\s*(?:default\s+)?` + regexp.QuoteMeta(name) + `\b`)
	return pattern.MatchString(policy)
}
