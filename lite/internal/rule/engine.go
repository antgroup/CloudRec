package rule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type Engine interface {
	Evaluate(ctx context.Context, pack RulePack, asset any) ([]FindingResult, error)
}

type Evaluator struct {
	Engine Engine
}

func NewEvaluator(engine Engine) Evaluator {
	if engine == nil {
		engine = NewOPAEngine()
	}
	return Evaluator{Engine: engine}
}

func (e Evaluator) Evaluate(ctx context.Context, packs []RulePack, asset any) ([]FindingResult, error) {
	if e.Engine == nil {
		return nil, errors.New("rule evaluator engine is nil")
	}

	var findings []FindingResult
	for _, pack := range packs {
		if pack.Metadata.Disabled {
			continue
		}
		packFindings, err := e.Engine.Evaluate(ctx, pack, asset)
		if err != nil {
			return nil, fmt.Errorf("evaluate rule %s: %w", pack.Metadata.ID, err)
		}
		findings = append(findings, packFindings...)
	}
	return findings, nil
}

type MockEngine struct {
	EvaluateFunc func(ctx context.Context, pack RulePack, asset any) ([]FindingResult, error)
}

func (m MockEngine) Evaluate(ctx context.Context, pack RulePack, asset any) ([]FindingResult, error) {
	if m.EvaluateFunc == nil {
		return nil, nil
	}
	return m.EvaluateFunc(ctx, pack, asset)
}

func normalizeAssetInput(asset any) (any, error) {
	switch value := asset.(type) {
	case nil:
		return map[string]any{}, nil
	case json.RawMessage:
		return decodeJSONInput(value)
	case []byte:
		return decodeJSONInput(value)
	case string:
		if strings.TrimSpace(value) == "" {
			return map[string]any{}, nil
		}
		return decodeJSONInput([]byte(value))
	case map[string]any, []any:
		return value, nil
	default:
		content, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("marshal asset input: %w", err)
		}
		return decodeJSONInput(content)
	}
}

func decodeJSONInput(content []byte) (any, error) {
	var value any
	if err := json.Unmarshal(content, &value); err != nil {
		return nil, fmt.Errorf("decode asset json: %w", err)
	}
	return value, nil
}
