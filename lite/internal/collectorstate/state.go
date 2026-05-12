package collectorstate

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	TaskStatusSucceeded = "succeeded"
	TaskStatusFailed    = "failed"
	TaskStatusSkipped   = "skipped"
)

type recorderContextKey struct{}
type skipCacheContextKey struct{}

type TaskRecord struct {
	Provider     string    `json:"provider"`
	AccountID    string    `json:"account_id"`
	Scope        string    `json:"scope"`
	ResourceType string    `json:"resource_type"`
	Region       string    `json:"region"`
	Status       string    `json:"status"`
	Category     string    `json:"category,omitempty"`
	Message      string    `json:"message,omitempty"`
	AssetCount   int       `json:"asset_count"`
	Attempt      int       `json:"attempt"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	DurationMs   int64     `json:"duration_ms"`
}

type TaskSummary struct {
	Total      int          `json:"total"`
	Succeeded  int          `json:"succeeded"`
	Failed     int          `json:"failed"`
	Skipped    int          `json:"skipped"`
	DurationMs int64        `json:"duration_ms"`
	Slowest    []TaskRecord `json:"slowest,omitempty"`
}

type Recorder struct {
	mu        sync.Mutex
	provider  string
	accountID string
	records   []TaskRecord
}

type TaskSpan struct {
	rec    *Recorder
	record TaskRecord
}

func NewRecorder(provider string, accountID string) *Recorder {
	return &Recorder{
		provider:  strings.TrimSpace(provider),
		accountID: strings.TrimSpace(accountID),
	}
}

func WithRecorder(ctx context.Context, recorder *Recorder) context.Context {
	if ctx == nil || recorder == nil {
		return ctx
	}
	return context.WithValue(ctx, recorderContextKey{}, recorder)
}

func RecorderFromContext(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	recorder, _ := ctx.Value(recorderContextKey{}).(*Recorder)
	return recorder
}

func StartTask(ctx context.Context, scope string, resourceType string, region string) *TaskSpan {
	recorder := RecorderFromContext(ctx)
	if recorder == nil {
		return &TaskSpan{}
	}
	return &TaskSpan{
		rec: recorder,
		record: TaskRecord{
			Provider:     recorder.provider,
			AccountID:    recorder.accountID,
			Scope:        strings.TrimSpace(scope),
			ResourceType: strings.TrimSpace(resourceType),
			Region:       strings.TrimSpace(region),
			Attempt:      1,
			StartedAt:    time.Now().UTC(),
		},
	}
}

func (s *TaskSpan) Done(taskErr error, category string, message string, assetCount int) {
	if s == nil || s.rec == nil {
		return
	}
	status := TaskStatusSucceeded
	if taskErr != nil {
		status = TaskStatusFailed
	}
	s.finish(status, category, message, assetCount)
}

func (s *TaskSpan) Skip(category string, message string) {
	if s == nil || s.rec == nil {
		return
	}
	s.finish(TaskStatusSkipped, category, message, 0)
}

func (s *TaskSpan) finish(status string, category string, message string, assetCount int) {
	finished := time.Now().UTC()
	record := s.record
	record.Status = strings.TrimSpace(status)
	record.Category = strings.TrimSpace(category)
	record.Message = trimMessage(message)
	record.AssetCount = assetCount
	record.FinishedAt = finished
	record.DurationMs = finished.Sub(record.StartedAt).Milliseconds()
	if record.DurationMs < 0 {
		record.DurationMs = 0
	}
	s.rec.add(record)
}

func (r *Recorder) add(record TaskRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, record)
}

func (r *Recorder) Snapshot() []TaskRecord {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	records := make([]TaskRecord, len(r.records))
	copy(records, r.records)
	return records
}

func Summarize(records []TaskRecord) TaskSummary {
	summary := TaskSummary{Total: len(records)}
	for _, record := range records {
		summary.DurationMs += record.DurationMs
		switch record.Status {
		case TaskStatusSucceeded:
			summary.Succeeded++
		case TaskStatusFailed:
			summary.Failed++
		case TaskStatusSkipped:
			summary.Skipped++
		}
	}

	slowest := make([]TaskRecord, len(records))
	copy(slowest, records)
	sort.SliceStable(slowest, func(i, j int) bool {
		return slowest[i].DurationMs > slowest[j].DurationMs
	})
	if len(slowest) > 10 {
		slowest = slowest[:10]
	}
	summary.Slowest = slowest
	return summary
}

type SkipEntry struct {
	Provider     string    `json:"provider"`
	AccountID    string    `json:"account_id"`
	ResourceType string    `json:"resource_type"`
	Region       string    `json:"region"`
	Category     string    `json:"category"`
	Message      string    `json:"message,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type SkipCache struct {
	mu        sync.Mutex
	provider  string
	accountID string
	ttl       time.Duration
	active    map[string]SkipEntry
	observed  map[string]SkipEntry
}

func NewSkipCache(provider string, accountID string, ttl time.Duration, entries []SkipEntry) *SkipCache {
	cache := &SkipCache{
		provider:  strings.TrimSpace(provider),
		accountID: strings.TrimSpace(accountID),
		ttl:       ttl,
		active:    map[string]SkipEntry{},
		observed:  map[string]SkipEntry{},
	}
	now := time.Now().UTC()
	for _, entry := range entries {
		if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(now) {
			continue
		}
		cache.active[cache.key(entry.ResourceType, entry.Region)] = entry
	}
	return cache
}

func WithSkipCache(ctx context.Context, cache *SkipCache) context.Context {
	if ctx == nil || cache == nil {
		return ctx
	}
	return context.WithValue(ctx, skipCacheContextKey{}, cache)
}

func SkipCacheFromContext(ctx context.Context) *SkipCache {
	if ctx == nil {
		return nil
	}
	cache, _ := ctx.Value(skipCacheContextKey{}).(*SkipCache)
	return cache
}

func LookupSkip(ctx context.Context, resourceType string, region string) (SkipEntry, bool) {
	cache := SkipCacheFromContext(ctx)
	if cache == nil {
		return SkipEntry{}, false
	}
	return cache.Lookup(resourceType, region)
}

func ObserveFailure(ctx context.Context, resourceType string, region string, category string, message string) {
	cache := SkipCacheFromContext(ctx)
	if cache == nil {
		return
	}
	cache.ObserveFailure(resourceType, region, category, message)
}

func (c *SkipCache) Lookup(resourceType string, region string) (SkipEntry, bool) {
	if c == nil {
		return SkipEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.active[c.key(resourceType, region)]
	if !ok {
		return SkipEntry{}, false
	}
	if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(time.Now().UTC()) {
		delete(c.active, c.key(resourceType, region))
		return SkipEntry{}, false
	}
	return entry, true
}

func (c *SkipCache) ObserveFailure(resourceType string, region string, category string, message string) {
	if c == nil || c.ttl <= 0 || !cacheableCategory(category) {
		return
	}
	entry := SkipEntry{
		Provider:     c.provider,
		AccountID:    c.accountID,
		ResourceType: strings.TrimSpace(resourceType),
		Region:       strings.TrimSpace(region),
		Category:     strings.TrimSpace(category),
		Message:      trimMessage(message),
		ExpiresAt:    time.Now().UTC().Add(c.ttl),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observed[c.key(resourceType, region)] = entry
}

func (c *SkipCache) Observed() []SkipEntry {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entries := make([]SkipEntry, 0, len(c.observed))
	for _, entry := range c.observed {
		entries = append(entries, entry)
	}
	return entries
}

func (c *SkipCache) key(resourceType string, region string) string {
	return strings.ToLower(strings.TrimSpace(resourceType)) + "\x00" + strings.ToLower(strings.TrimSpace(region))
}

func cacheableCategory(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "unsupported_region", "product_not_enabled", "permission":
		return true
	default:
		return false
	}
}

func trimMessage(message string) string {
	message = strings.TrimSpace(message)
	const limit = 500
	if len(message) <= limit {
		return message
	}
	return message[:limit]
}
