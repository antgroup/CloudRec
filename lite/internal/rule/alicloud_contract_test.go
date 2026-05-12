package rule

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAlicloudRulePackHasNoSingularPluralTopLevelInputMismatch(t *testing.T) {
	root := filepath.Join("..", "..", "rules", "alicloud")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	refPattern := regexp.MustCompile(`\binput\.([A-Za-z_][A-Za-z0-9_]*)`)
	var mismatches []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		policyPath := filepath.Join(dir, "policy.rego")
		inputPath := filepath.Join(dir, "input.json")
		policy, err := os.ReadFile(policyPath)
		if err != nil {
			continue
		}
		input, err := readTopLevelInputKeys(inputPath)
		if err != nil {
			t.Fatalf("read input keys for %s: %v", entry.Name(), err)
		}
		seen := map[string]struct{}{}
		for _, match := range refPattern.FindAllStringSubmatch(string(policy), -1) {
			ref := match[1]
			if _, ok := seen[ref]; ok {
				continue
			}
			seen[ref] = struct{}{}
			if _, ok := input[ref]; ok {
				continue
			}
			for _, candidate := range singularCandidates(ref) {
				if _, ok := input[candidate]; ok {
					mismatches = append(mismatches, fmt.Sprintf("%s references input.%s but fixture has %s", entry.Name(), ref, candidate))
				}
			}
		}
	}

	if len(mismatches) > 0 {
		t.Fatalf("singular/plural top-level input mismatches:\n%s", strings.Join(mismatches, "\n"))
	}
}

func readTopLevelInputKeys(path string) (map[string]struct{}, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var input map[string]any
	if err := json.Unmarshal(content, &input); err != nil {
		return nil, err
	}
	keys := make(map[string]struct{}, len(input))
	for key := range input {
		keys[key] = struct{}{}
	}
	return keys, nil
}

func singularCandidates(ref string) []string {
	var candidates []string
	if strings.HasSuffix(ref, "ies") && len(ref) > 3 {
		candidates = append(candidates, ref[:len(ref)-3]+"y")
	}
	if strings.HasSuffix(ref, "s") && len(ref) > 1 {
		candidates = append(candidates, ref[:len(ref)-1])
	}
	return candidates
}
