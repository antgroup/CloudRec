package progress

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type contextKey struct{}

type Reporter struct {
	mu     sync.Mutex
	writer io.Writer
}

type Tracker struct {
	reporter  *Reporter
	scope     string
	tasks     []string
	started   time.Time
	completed int
	elapsed   time.Duration
	current   string
}

func NewReporter(writer io.Writer) *Reporter {
	if writer == nil {
		return nil
	}
	return &Reporter{writer: writer}
}

func WithReporter(ctx context.Context, reporter *Reporter) context.Context {
	if reporter == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, reporter)
}

func FromContext(ctx context.Context) *Reporter {
	if ctx == nil {
		return nil
	}
	reporter, _ := ctx.Value(contextKey{}).(*Reporter)
	return reporter
}

func (r *Reporter) Tracker(scope string, tasks []string) *Tracker {
	if r == nil || r.writer == nil {
		return &Tracker{}
	}
	return &Tracker{
		reporter: r,
		scope:    strings.TrimSpace(scope),
		tasks:    compactTasks(tasks),
	}
}

func (t *Tracker) Start() {
	if t == nil || t.reporter == nil {
		return
	}
	t.started = time.Now()
	t.render("started", 0)
}

func (t *Tracker) TaskStart(task string) {
	if t == nil || t.reporter == nil {
		return
	}
	t.current = strings.TrimSpace(task)
	t.render("running", 0)
}

func (t *Tracker) TaskDone(task string, taskErr error, cost time.Duration) {
	if t == nil || t.reporter == nil {
		return
	}
	t.current = strings.TrimSpace(task)
	t.completed++
	t.elapsed += cost

	status := "done"
	if taskErr != nil {
		status = "error"
	}
	if taskErr != nil || t.completed == t.total() || t.completed%5 == 0 {
		t.render(status, cost)
	}
}

func (t *Tracker) Finish(status string) {
	if t == nil || t.reporter == nil {
		return
	}
	if strings.TrimSpace(status) == "" {
		status = "finished"
	}
	t.current = ""
	t.render(status, 0)
}

func (t *Tracker) render(status string, cost time.Duration) {
	total := t.total()
	if total == 0 {
		return
	}
	elapsed := t.elapsed
	if t.started.IsZero() {
		t.started = time.Now()
	}
	if elapsed == 0 {
		elapsed = time.Since(t.started)
	}
	remaining := total - t.completed
	if remaining < 0 {
		remaining = 0
	}

	current := t.current
	if current == "" && t.completed < len(t.tasks) {
		current = t.tasks[t.completed]
	}

	t.reporter.emit(
		"[progress] %s %s %d/%d %3.0f%% status=%s current=%s eta=%s pending=%s elapsed=%s%s\n",
		t.scope,
		progressBar(t.completed, total),
		t.completed,
		total,
		percent(t.completed, total),
		status,
		quoteValue(current),
		t.eta(remaining),
		formatPending(t.pending(current)),
		roundDuration(elapsed),
		formatCost(cost),
	)
}

func (t *Tracker) total() int {
	if len(t.tasks) > 0 {
		return len(t.tasks)
	}
	return 0
}

func (t *Tracker) eta(remaining int) string {
	if t.completed == 0 || remaining == 0 {
		if remaining == 0 {
			return "0s"
		}
		return "unknown"
	}
	avg := t.elapsed / time.Duration(t.completed)
	return roundDuration(avg * time.Duration(remaining))
}

func (t *Tracker) pending(current string) []string {
	if len(t.tasks) == 0 || t.completed >= len(t.tasks) {
		return nil
	}
	start := t.completed
	if current != "" && start < len(t.tasks) && t.tasks[start] == current {
		start++
	}
	if start >= len(t.tasks) {
		return nil
	}
	return t.tasks[start:]
}

func (r *Reporter) emit(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = fmt.Fprintf(r.writer, format, args...)
}

func compactTasks(tasks []string) []string {
	values := make([]string, 0, len(tasks))
	for _, task := range tasks {
		task = strings.TrimSpace(task)
		if task != "" {
			values = append(values, task)
		}
	}
	return values
}

func progressBar(completed int, total int) string {
	const width = 24
	if total <= 0 {
		return "[" + strings.Repeat("-", width) + "]"
	}
	if completed < 0 {
		completed = 0
	}
	if completed > total {
		completed = total
	}
	filled := completed * width / total
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", width-filled) + "]"
}

func percent(completed int, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(completed) * 100 / float64(total)
}

func formatPending(tasks []string) string {
	if len(tasks) == 0 {
		return "none"
	}
	const limit = 6
	values := tasks
	if len(values) > limit {
		values = values[:limit]
	}
	quoted := make([]string, 0, len(values))
	for _, task := range values {
		quoted = append(quoted, quoteValue(task))
	}
	if len(tasks) > limit {
		quoted = append(quoted, fmt.Sprintf("+%d more", len(tasks)-limit))
	}
	return strings.Join(quoted, ",")
}

func quoteValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	return fmt.Sprintf("%q", value)
}

func formatCost(cost time.Duration) string {
	if cost <= 0 {
		return ""
	}
	return " last=" + roundDuration(cost)
}

func roundDuration(value time.Duration) string {
	if value <= 0 {
		return "0s"
	}
	if value < time.Second {
		return "<1s"
	}
	return value.Round(time.Second).String()
}
