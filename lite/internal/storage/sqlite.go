package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/migrations"
	_ "modernc.org/sqlite"
)

const sqliteDriverName = "sqlite"

type SQLiteStore struct {
	db *sql.DB
}

func Open(ctx context.Context, dsn string) (*SQLiteStore, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("sqlite dsn is required")
	}

	db, err := sql.Open(sqliteDriverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	store := NewSQLiteStore(db)
	if err := store.configure(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

func (s *SQLiteStore) Init(ctx context.Context) error {
	schema, err := migrations.InitSQL()
	if err != nil {
		return fmt.Errorf("load schema: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialize schema: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) UpsertAccount(ctx context.Context, account model.Account) (model.Account, error) {
	if strings.TrimSpace(account.Provider) == "" {
		return model.Account{}, errors.New("account provider is required")
	}
	if account.ID == "" {
		id, err := newID()
		if err != nil {
			return model.Account{}, err
		}
		account.ID = id
	}

	now := utcNow()
	if account.CreatedAt.IsZero() {
		account.CreatedAt = now
	}
	account.UpdatedAt = now

	row := s.db.QueryRowContext(ctx, `
INSERT INTO accounts (
    id, provider, name, external_id, metadata_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    provider = excluded.provider,
    name = excluded.name,
    external_id = excluded.external_id,
    metadata_json = excluded.metadata_json,
    updated_at = excluded.updated_at
RETURNING id, provider, name, external_id, metadata_json, created_at, updated_at
`,
		account.ID,
		account.Provider,
		account.Name,
		account.ExternalID,
		jsonText(account.Metadata),
		formatTime(account.CreatedAt),
		formatTime(account.UpdatedAt),
	)
	return scanAccount(row)
}

func (s *SQLiteStore) CreateScanRun(ctx context.Context, run model.ScanRun) (model.ScanRun, error) {
	if strings.TrimSpace(run.AccountID) == "" {
		return model.ScanRun{}, errors.New("scan run account id is required")
	}
	if strings.TrimSpace(run.Provider) == "" {
		return model.ScanRun{}, errors.New("scan run provider is required")
	}
	if run.ID == "" {
		id, err := newID()
		if err != nil {
			return model.ScanRun{}, err
		}
		run.ID = id
	}
	if run.Status == "" {
		run.Status = model.ScanRunStatusRunning
	}

	now := utcNow()
	if run.StartedAt.IsZero() {
		run.StartedAt = now
	}
	if run.CreatedAt.IsZero() {
		run.CreatedAt = now
	}
	run.UpdatedAt = now

	row := s.db.QueryRowContext(ctx, `
INSERT INTO scan_runs (
    id, account_id, provider, status, started_at, finished_at, summary_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, account_id, provider, status, started_at, finished_at, summary_json, created_at, updated_at
`,
		run.ID,
		run.AccountID,
		run.Provider,
		run.Status,
		formatTime(run.StartedAt),
		formatOptionalTime(run.FinishedAt),
		jsonText(run.Summary),
		formatTime(run.CreatedAt),
		formatTime(run.UpdatedAt),
	)
	return scanScanRun(row)
}

func (s *SQLiteStore) FinishScanRun(ctx context.Context, id string, status string, summary json.RawMessage) (model.ScanRun, error) {
	if strings.TrimSpace(id) == "" {
		return model.ScanRun{}, errors.New("scan run id is required")
	}
	if strings.TrimSpace(status) == "" {
		return model.ScanRun{}, errors.New("scan run status is required")
	}

	now := utcNow()
	row := s.db.QueryRowContext(ctx, `
UPDATE scan_runs
SET status = ?, finished_at = ?, summary_json = ?, updated_at = ?
WHERE id = ?
RETURNING id, account_id, provider, status, started_at, finished_at, summary_json, created_at, updated_at
`,
		status,
		formatTime(now),
		jsonText(summary),
		formatTime(now),
		id,
	)
	return scanScanRun(row)
}

func (s *SQLiteStore) ListScanRuns(ctx context.Context, filter ScanRunFilter) ([]model.ScanRun, error) {
	var (
		query strings.Builder
		args  []any
	)

	query.WriteString(`
SELECT id, account_id, provider, status, started_at, finished_at, summary_json, created_at, updated_at
FROM scan_runs
`)
	clause, whereArgs := scanRunWhereClause("scan_runs", filter)
	query.WriteString(clause)
	args = append(args, whereArgs...)
	query.WriteString(scanRunOrderBy(filter.Sort))
	appendLimit(&query, &args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("list scan runs: %w", err)
	}
	defer rows.Close()

	var runs []model.ScanRun
	for rows.Next() {
		run, err := scanScanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan runs: %w", err)
	}
	return runs, nil
}

func (s *SQLiteStore) ListScanRunsWithTotal(ctx context.Context, filter ScanRunFilter) (model.ScanRunList, error) {
	total, err := s.CountScanRuns(ctx, filter)
	if err != nil {
		return model.ScanRunList{}, err
	}
	runs, err := s.ListScanRuns(ctx, filter)
	if err != nil {
		return model.ScanRunList{}, err
	}
	if runs == nil {
		runs = []model.ScanRun{}
	}
	return model.ScanRunList{
		ScanRuns: runs,
		Total:    total,
		Offset:   filter.Offset,
		Limit:    filter.Limit,
	}, nil
}

func (s *SQLiteStore) CountScanRuns(ctx context.Context, filter ScanRunFilter) (int, error) {
	clause, args := scanRunWhereClause("scan_runs", filter)
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_runs"+clause, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count scan runs: %w", err)
	}
	return count, nil
}

func (s *SQLiteStore) InsertScanTaskRun(ctx context.Context, task model.ScanTaskRun) (model.ScanTaskRun, error) {
	if strings.TrimSpace(task.ScanRunID) == "" {
		return model.ScanTaskRun{}, errors.New("scan task run scan run id is required")
	}
	if strings.TrimSpace(task.AccountID) == "" {
		return model.ScanTaskRun{}, errors.New("scan task run account id is required")
	}
	if strings.TrimSpace(task.Provider) == "" {
		return model.ScanTaskRun{}, errors.New("scan task run provider is required")
	}
	if strings.TrimSpace(task.Status) == "" {
		return model.ScanTaskRun{}, errors.New("scan task run status is required")
	}
	if task.ID == "" {
		id, err := newID()
		if err != nil {
			return model.ScanTaskRun{}, err
		}
		task.ID = id
	}
	if task.Attempt <= 0 {
		task.Attempt = 1
	}
	now := utcNow()
	if task.StartedAt.IsZero() {
		task.StartedAt = now
	}
	if task.FinishedAt.IsZero() {
		task.FinishedAt = task.StartedAt
	}
	if task.CreatedAt.IsZero() {
		task.CreatedAt = now
	}

	row := s.db.QueryRowContext(ctx, scanTaskRunInsertSQL(), scanTaskRunArgs(task)...)
	return scanScanTaskRun(row)
}

func (s *SQLiteStore) InsertScanTaskRuns(ctx context.Context, tasks []model.ScanTaskRun) error {
	if len(tasks) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin scan task run insert: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, scanTaskRunInsertNoReturnSQL())
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare scan task run insert: %w", err)
	}
	defer stmt.Close()

	for _, task := range tasks {
		if strings.TrimSpace(task.ScanRunID) == "" {
			_ = tx.Rollback()
			return errors.New("scan task run scan run id is required")
		}
		if strings.TrimSpace(task.AccountID) == "" {
			_ = tx.Rollback()
			return errors.New("scan task run account id is required")
		}
		if strings.TrimSpace(task.Provider) == "" {
			_ = tx.Rollback()
			return errors.New("scan task run provider is required")
		}
		if strings.TrimSpace(task.Status) == "" {
			_ = tx.Rollback()
			return errors.New("scan task run status is required")
		}
		if task.ID == "" {
			id, err := newID()
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			task.ID = id
		}
		if task.Attempt <= 0 {
			task.Attempt = 1
		}
		now := utcNow()
		if task.StartedAt.IsZero() {
			task.StartedAt = now
		}
		if task.FinishedAt.IsZero() {
			task.FinishedAt = task.StartedAt
		}
		if task.CreatedAt.IsZero() {
			task.CreatedAt = now
		}
		if _, err := stmt.ExecContext(ctx, scanTaskRunArgs(task)...); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert scan task run: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan task run insert: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListScanTaskRuns(ctx context.Context, filter ScanTaskRunFilter) ([]model.ScanTaskRun, error) {
	var (
		query strings.Builder
		args  []any
	)
	query.WriteString(`
SELECT id, scan_run_id, account_id, provider, scope, resource_type, region, status, category, message,
    asset_count, attempt, started_at, finished_at, duration_ms, created_at
FROM scan_task_runs
`)
	clause, whereArgs := scanTaskRunWhereClause("scan_task_runs", filter)
	query.WriteString(clause)
	args = append(args, whereArgs...)
	query.WriteString(scanTaskRunOrderBy(filter.Sort))
	appendLimit(&query, &args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("list scan task runs: %w", err)
	}
	defer rows.Close()

	var tasks []model.ScanTaskRun
	for rows.Next() {
		task, err := scanScanTaskRun(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan task runs: %w", err)
	}
	return tasks, nil
}

func (s *SQLiteStore) ListActiveCollectorSkipEntries(ctx context.Context, providerName string, accountID string, now time.Time) ([]model.CollectorSkipEntry, error) {
	if now.IsZero() {
		now = utcNow()
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, account_id, provider, resource_type, region, category, message, expires_at, created_at, updated_at
FROM collector_skip_cache
WHERE provider = ? AND account_id = ? AND expires_at > ?
ORDER BY resource_type, region, category
`, strings.TrimSpace(providerName), strings.TrimSpace(accountID), formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("list collector skip cache: %w", err)
	}
	defer rows.Close()

	var entries []model.CollectorSkipEntry
	for rows.Next() {
		entry, err := scanCollectorSkipEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate collector skip cache: %w", err)
	}
	return entries, nil
}

func (s *SQLiteStore) UpsertCollectorSkipEntry(ctx context.Context, entry model.CollectorSkipEntry) (model.CollectorSkipEntry, error) {
	if strings.TrimSpace(entry.AccountID) == "" {
		return model.CollectorSkipEntry{}, errors.New("collector skip entry account id is required")
	}
	if strings.TrimSpace(entry.Provider) == "" {
		return model.CollectorSkipEntry{}, errors.New("collector skip entry provider is required")
	}
	if strings.TrimSpace(entry.ResourceType) == "" {
		return model.CollectorSkipEntry{}, errors.New("collector skip entry resource type is required")
	}
	if strings.TrimSpace(entry.Category) == "" {
		return model.CollectorSkipEntry{}, errors.New("collector skip entry category is required")
	}
	if entry.ExpiresAt.IsZero() {
		return model.CollectorSkipEntry{}, errors.New("collector skip entry expires at is required")
	}
	if entry.ID == "" {
		id, err := newID()
		if err != nil {
			return model.CollectorSkipEntry{}, err
		}
		entry.ID = id
	}
	now := utcNow()
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = now
	}
	entry.UpdatedAt = now

	row := s.db.QueryRowContext(ctx, `
INSERT INTO collector_skip_cache (
    id, account_id, provider, resource_type, region, category, message, expires_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(account_id, provider, resource_type, region, category) DO UPDATE SET
    message = excluded.message,
    expires_at = excluded.expires_at,
    updated_at = excluded.updated_at
RETURNING id, account_id, provider, resource_type, region, category, message, expires_at, created_at, updated_at
`,
		entry.ID,
		entry.AccountID,
		entry.Provider,
		entry.ResourceType,
		entry.Region,
		entry.Category,
		entry.Message,
		formatTime(entry.ExpiresAt),
		formatTime(entry.CreatedAt),
		formatTime(entry.UpdatedAt),
	)
	return scanCollectorSkipEntry(row)
}

func (s *SQLiteStore) UpsertCollectorSkipEntries(ctx context.Context, entries []model.CollectorSkipEntry) error {
	for _, entry := range entries {
		if _, err := s.UpsertCollectorSkipEntry(ctx, entry); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) UpsertAsset(ctx context.Context, asset model.Asset) (model.Asset, error) {
	if strings.TrimSpace(asset.AccountID) == "" {
		return model.Asset{}, errors.New("asset account id is required")
	}
	if strings.TrimSpace(asset.Provider) == "" {
		return model.Asset{}, errors.New("asset provider is required")
	}
	if strings.TrimSpace(asset.ResourceType) == "" {
		return model.Asset{}, errors.New("asset resource type is required")
	}
	if strings.TrimSpace(asset.ResourceID) == "" {
		return model.Asset{}, errors.New("asset resource id is required")
	}
	if asset.ID == "" {
		id, err := newID()
		if err != nil {
			return model.Asset{}, err
		}
		asset.ID = id
	}

	now := utcNow()
	if asset.FirstSeenAt.IsZero() {
		asset.FirstSeenAt = now
	}
	if asset.LastSeenAt.IsZero() {
		asset.LastSeenAt = now
	}
	if asset.CreatedAt.IsZero() {
		asset.CreatedAt = now
	}
	asset.UpdatedAt = now

	row := s.db.QueryRowContext(ctx, `
INSERT INTO assets (
    id, account_id, provider, resource_type, resource_id, region, name, properties_json,
    first_seen_at, last_seen_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(account_id, resource_type, resource_id) DO UPDATE SET
    provider = excluded.provider,
    region = excluded.region,
    name = excluded.name,
    properties_json = excluded.properties_json,
    last_seen_at = excluded.last_seen_at,
    updated_at = excluded.updated_at
RETURNING id, account_id, provider, resource_type, resource_id, region, name, properties_json,
    first_seen_at, last_seen_at, created_at, updated_at
`,
		asset.ID,
		asset.AccountID,
		asset.Provider,
		asset.ResourceType,
		asset.ResourceID,
		asset.Region,
		asset.Name,
		jsonText(asset.Properties),
		formatTime(asset.FirstSeenAt),
		formatTime(asset.LastSeenAt),
		formatTime(asset.CreatedAt),
		formatTime(asset.UpdatedAt),
	)
	return scanAsset(row)
}

func (s *SQLiteStore) ListAssets(ctx context.Context, filter AssetFilter) ([]model.Asset, error) {
	var (
		query strings.Builder
		args  []any
	)

	query.WriteString(`
SELECT id, account_id, provider, resource_type, resource_id, region, name, properties_json,
    first_seen_at, last_seen_at, created_at, updated_at
FROM assets
`)
	clause, whereArgs := assetWhereClause("assets", filter)
	query.WriteString(clause)
	args = append(args, whereArgs...)
	query.WriteString(assetOrderBy(filter.Sort, "assets"))
	appendLimit(&query, &args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()

	var assets []model.Asset
	for rows.Next() {
		asset, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assets: %w", err)
	}
	return assets, nil
}

func (s *SQLiteStore) ListAssetsWithTotal(ctx context.Context, filter AssetFilter) (model.AssetList, error) {
	total, err := s.CountAssets(ctx, filter)
	if err != nil {
		return model.AssetList{}, err
	}
	assets, err := s.ListAssets(ctx, filter)
	if err != nil {
		return model.AssetList{}, err
	}
	if assets == nil {
		assets = []model.Asset{}
	}
	return model.AssetList{
		Assets: assets,
		Total:  total,
		Offset: filter.Offset,
		Limit:  filter.Limit,
	}, nil
}

func (s *SQLiteStore) CountAssets(ctx context.Context, filter AssetFilter) (int, error) {
	clause, args := assetWhereClause("assets", filter)
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM assets"+clause, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count assets: %w", err)
	}
	return count, nil
}

func (s *SQLiteStore) ListAssetViews(ctx context.Context, filter AssetFilter) (model.AssetViewList, error) {
	total, err := s.CountAssets(ctx, filter)
	if err != nil {
		return model.AssetViewList{}, err
	}

	var (
		query strings.Builder
		args  []any
	)
	query.WriteString(`
SELECT a.id, a.account_id, a.provider, a.resource_type, a.resource_id, a.region, a.name, a.properties_json,
    a.first_seen_at, a.last_seen_at, a.created_at, a.updated_at,
    COUNT(f.id) AS finding_count,
    SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS open_finding_count,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_finding_count,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_finding_count
FROM assets a
LEFT JOIN findings f ON f.asset_id = a.id
`)
	clause, whereArgs := assetWhereClause("a", filter)
	query.WriteString(clause)
	args = append(args, whereArgs...)
	query.WriteString(`
GROUP BY a.id, a.account_id, a.provider, a.resource_type, a.resource_id, a.region, a.name, a.properties_json,
    a.first_seen_at, a.last_seen_at, a.created_at, a.updated_at
`)
	query.WriteString(assetViewOrderBy(filter.Sort))
	appendLimit(&query, &args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return model.AssetViewList{}, fmt.Errorf("list asset views: %w", err)
	}
	defer rows.Close()

	assets := make([]model.AssetView, 0)
	for rows.Next() {
		view, err := scanAssetViewSummary(rows)
		if err != nil {
			return model.AssetViewList{}, err
		}
		assets = append(assets, view)
	}
	if err := rows.Err(); err != nil {
		return model.AssetViewList{}, fmt.Errorf("iterate asset views: %w", err)
	}
	return model.AssetViewList{
		Assets: assets,
		Total:  total,
		Offset: filter.Offset,
		Limit:  filter.Limit,
	}, nil
}

func (s *SQLiteStore) GetAsset(ctx context.Context, id string) (model.AssetView, error) {
	return s.GetAssetView(ctx, id)
}

func (s *SQLiteStore) GetAssetView(ctx context.Context, id string) (model.AssetView, error) {
	if strings.TrimSpace(id) == "" {
		return model.AssetView{}, errors.New("asset id is required")
	}

	row := s.db.QueryRowContext(ctx, `
SELECT a.id, a.account_id, a.provider, a.resource_type, a.resource_id, a.region, a.name, a.properties_json,
    a.first_seen_at, a.last_seen_at, a.created_at, a.updated_at,
    COUNT(f.id) AS finding_count,
    SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS open_finding_count,
    SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_finding_count,
    SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_finding_count
FROM assets a
LEFT JOIN findings f ON f.asset_id = a.id
WHERE a.id = ?
GROUP BY a.id, a.account_id, a.provider, a.resource_type, a.resource_id, a.region, a.name, a.properties_json,
    a.first_seen_at, a.last_seen_at, a.created_at, a.updated_at
`, strings.TrimSpace(id))
	view, err := scanAssetViewSummary(row)
	if err != nil {
		return model.AssetView{}, err
	}
	view.SeverityCounts, err = s.findingSeverityCounts(ctx, view.ID, "")
	if err != nil {
		return model.AssetView{}, err
	}
	relationships, err := s.ListAssetRelationships(ctx, RelationshipFilter{
		AccountID:     view.AccountID,
		SourceAssetID: view.ID,
	})
	if err != nil {
		return model.AssetView{}, err
	}
	view.Relationships = relationships

	findings, err := s.ListFindingViews(ctx, FindingFilter{
		AccountID: view.AccountID,
		AssetID:   view.ID,
		Limit:     100,
	})
	if err != nil {
		return model.AssetView{}, err
	}
	view.Findings = findings.Findings
	return view, nil
}

func (s *SQLiteStore) UpsertAssetRelationship(ctx context.Context, relationship model.AssetRelationship) (model.AssetRelationship, error) {
	if strings.TrimSpace(relationship.AccountID) == "" {
		return model.AssetRelationship{}, errors.New("relationship account id is required")
	}
	if strings.TrimSpace(relationship.Provider) == "" {
		return model.AssetRelationship{}, errors.New("relationship provider is required")
	}
	if strings.TrimSpace(relationship.SourceAssetID) == "" {
		return model.AssetRelationship{}, errors.New("relationship source asset id is required")
	}
	if strings.TrimSpace(relationship.SourceResourceType) == "" {
		return model.AssetRelationship{}, errors.New("relationship source resource type is required")
	}
	if strings.TrimSpace(relationship.SourceResourceID) == "" {
		return model.AssetRelationship{}, errors.New("relationship source resource id is required")
	}
	if strings.TrimSpace(relationship.RelationshipType) == "" {
		return model.AssetRelationship{}, errors.New("relationship type is required")
	}
	if strings.TrimSpace(relationship.TargetResourceID) == "" {
		return model.AssetRelationship{}, errors.New("relationship target resource id is required")
	}
	if relationship.ID == "" {
		id, err := newID()
		if err != nil {
			return model.AssetRelationship{}, err
		}
		relationship.ID = id
	}

	now := utcNow()
	if relationship.FirstSeenAt.IsZero() {
		relationship.FirstSeenAt = now
	}
	if relationship.LastSeenAt.IsZero() {
		relationship.LastSeenAt = now
	}
	if relationship.CreatedAt.IsZero() {
		relationship.CreatedAt = now
	}
	relationship.UpdatedAt = now

	row := s.db.QueryRowContext(ctx, `
INSERT INTO asset_relationships (
    id, account_id, provider, source_asset_id, source_resource_type, source_resource_id,
    relationship_type, target_resource_id, properties_json, first_seen_at, last_seen_at,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(account_id, source_asset_id, relationship_type, target_resource_id) DO UPDATE SET
    provider = excluded.provider,
    source_resource_type = excluded.source_resource_type,
    source_resource_id = excluded.source_resource_id,
    properties_json = excluded.properties_json,
    last_seen_at = excluded.last_seen_at,
    updated_at = excluded.updated_at
RETURNING id, account_id, provider, source_asset_id, source_resource_type, source_resource_id,
    relationship_type, target_resource_id, properties_json, first_seen_at, last_seen_at,
    created_at, updated_at
`,
		relationship.ID,
		relationship.AccountID,
		relationship.Provider,
		relationship.SourceAssetID,
		relationship.SourceResourceType,
		relationship.SourceResourceID,
		relationship.RelationshipType,
		relationship.TargetResourceID,
		jsonText(relationship.Properties),
		formatTime(relationship.FirstSeenAt),
		formatTime(relationship.LastSeenAt),
		formatTime(relationship.CreatedAt),
		formatTime(relationship.UpdatedAt),
	)
	return scanAssetRelationship(row)
}

func (s *SQLiteStore) ListAssetRelationships(ctx context.Context, filter RelationshipFilter) ([]model.AssetRelationship, error) {
	var (
		query strings.Builder
		args  []any
	)

	query.WriteString(`
SELECT r.id, r.account_id, r.provider, r.source_asset_id, r.source_resource_type, r.source_resource_id,
    r.relationship_type, r.target_resource_id, r.properties_json, r.first_seen_at, r.last_seen_at,
    r.created_at, r.updated_at
FROM asset_relationships r
JOIN assets a ON a.id = r.source_asset_id
`)
	clause, whereArgs := relationshipWhereClause("r", "a", filter)
	query.WriteString(clause)
	args = append(args, whereArgs...)
	query.WriteString(relationshipOrderBy(filter.Sort, "r"))
	appendLimit(&query, &args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("list asset relationships: %w", err)
	}
	defer rows.Close()

	var relationships []model.AssetRelationship
	for rows.Next() {
		relationship, err := scanAssetRelationship(rows)
		if err != nil {
			return nil, err
		}
		relationships = append(relationships, relationship)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset relationships: %w", err)
	}
	return relationships, nil
}

func (s *SQLiteStore) ListAssetRelationshipsWithTotal(ctx context.Context, filter RelationshipFilter) (model.AssetRelationshipList, error) {
	total, err := s.CountAssetRelationships(ctx, filter)
	if err != nil {
		return model.AssetRelationshipList{}, err
	}
	relationships, err := s.ListAssetRelationships(ctx, filter)
	if err != nil {
		return model.AssetRelationshipList{}, err
	}
	if relationships == nil {
		relationships = []model.AssetRelationship{}
	}
	return model.AssetRelationshipList{
		Relationships: relationships,
		Total:         total,
		Offset:        filter.Offset,
		Limit:         filter.Limit,
	}, nil
}

func (s *SQLiteStore) CountAssetRelationships(ctx context.Context, filter RelationshipFilter) (int, error) {
	clause, args := relationshipWhereClause("r", "a", filter)
	var count int
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM asset_relationships r
JOIN assets a ON a.id = r.source_asset_id
`+clause, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count asset relationships: %w", err)
	}
	return count, nil
}

func (s *SQLiteStore) UpsertAssetScanState(ctx context.Context, state model.AssetScanState) (model.AssetScanState, error) {
	if strings.TrimSpace(state.ScanRunID) == "" {
		return model.AssetScanState{}, errors.New("asset scan state scan run id is required")
	}
	if strings.TrimSpace(state.AccountID) == "" {
		return model.AssetScanState{}, errors.New("asset scan state account id is required")
	}
	if strings.TrimSpace(state.AssetID) == "" {
		return model.AssetScanState{}, errors.New("asset scan state asset id is required")
	}
	if strings.TrimSpace(state.ResourceType) == "" {
		return model.AssetScanState{}, errors.New("asset scan state resource type is required")
	}
	if strings.TrimSpace(state.ResourceID) == "" {
		return model.AssetScanState{}, errors.New("asset scan state resource id is required")
	}
	if strings.TrimSpace(state.Status) == "" {
		return model.AssetScanState{}, errors.New("asset scan state status is required")
	}
	if state.ID == "" {
		id, err := newID()
		if err != nil {
			return model.AssetScanState{}, err
		}
		state.ID = id
	}

	now := utcNow()
	if state.CreatedAt.IsZero() {
		state.CreatedAt = now
	}
	state.UpdatedAt = now

	row := s.db.QueryRowContext(ctx, `
INSERT INTO asset_scan_states (
    id, scan_run_id, account_id, asset_id, resource_type, resource_id, status, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(scan_run_id, asset_id) DO UPDATE SET
    account_id = excluded.account_id,
    resource_type = excluded.resource_type,
    resource_id = excluded.resource_id,
    status = excluded.status,
    updated_at = excluded.updated_at
RETURNING id, scan_run_id, account_id, asset_id, resource_type, resource_id, status, created_at, updated_at
`,
		state.ID,
		state.ScanRunID,
		state.AccountID,
		state.AssetID,
		state.ResourceType,
		state.ResourceID,
		state.Status,
		formatTime(state.CreatedAt),
		formatTime(state.UpdatedAt),
	)
	return scanAssetScanState(row)
}

func (s *SQLiteStore) UpsertFinding(ctx context.Context, finding model.Finding) (model.Finding, error) {
	if strings.TrimSpace(finding.ScanRunID) == "" {
		return model.Finding{}, errors.New("finding scan run id is required")
	}
	if strings.TrimSpace(finding.AccountID) == "" {
		return model.Finding{}, errors.New("finding account id is required")
	}
	if strings.TrimSpace(finding.AssetID) == "" {
		return model.Finding{}, errors.New("finding asset id is required")
	}
	if strings.TrimSpace(finding.RuleID) == "" {
		return model.Finding{}, errors.New("finding rule id is required")
	}
	if finding.ID == "" {
		id, err := newID()
		if err != nil {
			return model.Finding{}, err
		}
		finding.ID = id
	}
	if finding.Severity == "" {
		finding.Severity = model.SeverityUnknown
	}
	if finding.Status == "" {
		finding.Status = model.FindingStatusOpen
	}

	now := utcNow()
	if finding.FirstSeenAt.IsZero() {
		finding.FirstSeenAt = now
	}
	if finding.LastSeenAt.IsZero() {
		finding.LastSeenAt = now
	}
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = now
	}
	finding.UpdatedAt = now

	row := s.db.QueryRowContext(ctx, `
INSERT INTO findings (
    id, scan_run_id, account_id, asset_id, rule_id, title, severity, status, message,
    evidence_json, remediation, first_seen_at, last_seen_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(scan_run_id, rule_id, asset_id) DO UPDATE SET
    account_id = excluded.account_id,
    title = excluded.title,
    severity = excluded.severity,
    status = excluded.status,
    message = excluded.message,
    evidence_json = excluded.evidence_json,
    remediation = excluded.remediation,
    last_seen_at = excluded.last_seen_at,
    updated_at = excluded.updated_at
RETURNING id, scan_run_id, account_id, asset_id, rule_id, title, severity, status, message,
    evidence_json, remediation, first_seen_at, last_seen_at, created_at, updated_at
`,
		finding.ID,
		finding.ScanRunID,
		finding.AccountID,
		finding.AssetID,
		finding.RuleID,
		finding.Title,
		finding.Severity,
		finding.Status,
		finding.Message,
		jsonText(finding.Evidence),
		finding.Remediation,
		formatTime(finding.FirstSeenAt),
		formatTime(finding.LastSeenAt),
		formatTime(finding.CreatedAt),
		formatTime(finding.UpdatedAt),
	)
	return scanFinding(row)
}

func (s *SQLiteStore) ListFindings(ctx context.Context, filter FindingFilter) ([]model.Finding, error) {
	var (
		query strings.Builder
		args  []any
	)

	query.WriteString(`
SELECT f.id, f.scan_run_id, f.account_id, f.asset_id, f.rule_id, f.title, f.severity, f.status, f.message,
    f.evidence_json, f.remediation, f.first_seen_at, f.last_seen_at, f.created_at, f.updated_at
FROM findings f
JOIN assets a ON a.id = f.asset_id
`)
	clause, whereArgs := findingWhereClause("f", "a", filter)
	query.WriteString(clause)
	args = append(args, whereArgs...)
	query.WriteString(findingOrderBy(filter.Sort, "f", "a"))
	appendLimit(&query, &args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var findings []model.Finding
	for rows.Next() {
		finding, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return findings, nil
}

func (s *SQLiteStore) ListFindingsWithTotal(ctx context.Context, filter FindingFilter) (model.FindingList, error) {
	total, err := s.CountFindings(ctx, filter)
	if err != nil {
		return model.FindingList{}, err
	}
	findings, err := s.ListFindings(ctx, filter)
	if err != nil {
		return model.FindingList{}, err
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	return model.FindingList{
		Findings: findings,
		Total:    total,
		Offset:   filter.Offset,
		Limit:    filter.Limit,
	}, nil
}

func (s *SQLiteStore) CountFindings(ctx context.Context, filter FindingFilter) (int, error) {
	clause, args := findingWhereClause("f", "a", filter)
	var count int
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM findings f
JOIN assets a ON a.id = f.asset_id
`+clause, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count findings: %w", err)
	}
	return count, nil
}

func (s *SQLiteStore) ListFindingViews(ctx context.Context, filter FindingFilter) (model.FindingViewList, error) {
	total, err := s.CountFindings(ctx, filter)
	if err != nil {
		return model.FindingViewList{}, err
	}

	var (
		query strings.Builder
		args  []any
	)
	query.WriteString(findingViewSelectSQL())
	clause, whereArgs := findingWhereClause("f", "a", filter)
	query.WriteString(clause)
	args = append(args, whereArgs...)
	query.WriteString(findingOrderBy(filter.Sort, "f", "a"))
	appendLimit(&query, &args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return model.FindingViewList{}, fmt.Errorf("list finding views: %w", err)
	}
	defer rows.Close()

	findings := make([]model.FindingView, 0)
	for rows.Next() {
		view, err := scanFindingView(rows)
		if err != nil {
			return model.FindingViewList{}, err
		}
		findings = append(findings, view)
	}
	if err := rows.Err(); err != nil {
		return model.FindingViewList{}, fmt.Errorf("iterate finding views: %w", err)
	}
	return model.FindingViewList{
		Findings: findings,
		Total:    total,
		Offset:   filter.Offset,
		Limit:    filter.Limit,
	}, nil
}

func (s *SQLiteStore) GetFinding(ctx context.Context, id string) (model.FindingView, error) {
	return s.GetFindingView(ctx, id)
}

func (s *SQLiteStore) GetFindingView(ctx context.Context, id string) (model.FindingView, error) {
	if strings.TrimSpace(id) == "" {
		return model.FindingView{}, errors.New("finding id is required")
	}

	row := s.db.QueryRowContext(ctx, findingViewSelectSQL()+" WHERE f.id = ?", strings.TrimSpace(id))
	view, err := scanFindingView(row)
	if err != nil {
		return model.FindingView{}, err
	}
	return view, nil
}

func (s *SQLiteStore) GetSummary(ctx context.Context, filter SummaryFilter) (model.Summary, error) {
	summary := model.Summary{
		AccountID:      strings.TrimSpace(filter.AccountID),
		SeverityCounts: map[string]int{},
	}

	accountClause, args := accountWhereClause(filter.AccountID)

	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM assets"+accountClause, args...).Scan(&summary.AssetCount); err != nil {
		return model.Summary{}, fmt.Errorf("count assets: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM asset_relationships"+accountClause, args...).Scan(&summary.RelationshipCount); err != nil {
		return model.Summary{}, fmt.Errorf("count asset relationships: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings"+accountClause, args...).Scan(&summary.FindingCount); err != nil {
		return model.Summary{}, fmt.Errorf("count findings: %w", err)
	}

	openClause := accountClause
	openArgs := append([]any(nil), args...)
	if openClause == "" {
		openClause = " WHERE status = ?"
	} else {
		openClause += " AND status = ?"
	}
	openArgs = append(openArgs, model.FindingStatusOpen)
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings"+openClause, openArgs...).Scan(&summary.OpenFindingCount); err != nil {
		return model.Summary{}, fmt.Errorf("count open findings: %w", err)
	}

	severityRows, err := s.db.QueryContext(ctx, "SELECT severity, COUNT(*) FROM findings"+accountClause+" GROUP BY severity", args...)
	if err != nil {
		return model.Summary{}, fmt.Errorf("count findings by severity: %w", err)
	}
	for severityRows.Next() {
		var severity string
		var count int
		if err := severityRows.Scan(&severity, &count); err != nil {
			_ = severityRows.Close()
			return model.Summary{}, fmt.Errorf("scan severity count: %w", err)
		}
		summary.SeverityCounts[severity] = count
	}
	if err := severityRows.Close(); err != nil {
		return model.Summary{}, fmt.Errorf("close severity rows: %w", err)
	}
	if err := severityRows.Err(); err != nil {
		return model.Summary{}, fmt.Errorf("iterate severity counts: %w", err)
	}

	runs, err := s.ListScanRuns(ctx, ScanRunFilter{
		AccountID: filter.AccountID,
		Limit:     1,
	})
	if err != nil {
		return model.Summary{}, err
	}
	if len(runs) > 0 {
		summary.LatestScanRun = &runs[0]
		summary.ScanDelta = scanDeltaFromSummary(runs[0].Summary)
	}

	return summary, nil
}

func (s *SQLiteStore) GetDashboard(ctx context.Context, filter DashboardFilter) (model.Dashboard, error) {
	summary, err := s.GetSummary(ctx, SummaryFilter{AccountID: filter.AccountID})
	if err != nil {
		return model.Dashboard{}, err
	}

	dashboard := model.Dashboard{
		AccountID:          strings.TrimSpace(filter.AccountID),
		Summary:            summary,
		AssetCount:         summary.AssetCount,
		FindingCount:       summary.FindingCount,
		OpenFindingCount:   summary.OpenFindingCount,
		RelationshipCount:  summary.RelationshipCount,
		SeverityCounts:     cloneIntMap(summary.SeverityCounts),
		StatusCounts:       map[string]int{},
		LatestScanRun:      summary.LatestScanRun,
		ScanDelta:          summary.ScanDelta,
		ProviderCounts:     []model.FacetValue{},
		RegionCounts:       []model.FacetValue{},
		ResourceTypeCounts: []model.FacetValue{},
		RecentFindings:     []model.FindingView{},
		RecentAssets:       []model.AssetView{},
	}

	baseAssetFilter := AssetFilter{
		AccountID: strings.TrimSpace(filter.AccountID),
		Provider:  strings.TrimSpace(filter.Provider),
		Region:    strings.TrimSpace(filter.Region),
	}
	baseFindingFilter := FindingFilter{
		AccountID: strings.TrimSpace(filter.AccountID),
		Provider:  strings.TrimSpace(filter.Provider),
		Region:    strings.TrimSpace(filter.Region),
	}

	if strings.TrimSpace(filter.Provider) != "" || strings.TrimSpace(filter.Region) != "" {
		dashboard.AssetCount, err = s.CountAssets(ctx, baseAssetFilter)
		if err != nil {
			return model.Dashboard{}, err
		}
		dashboard.FindingCount, err = s.CountFindings(ctx, baseFindingFilter)
		if err != nil {
			return model.Dashboard{}, err
		}
		dashboard.OpenFindingCount, err = s.CountFindings(ctx, FindingFilter{
			AccountID: baseFindingFilter.AccountID,
			Provider:  baseFindingFilter.Provider,
			Region:    baseFindingFilter.Region,
			Status:    model.FindingStatusOpen,
		})
		if err != nil {
			return model.Dashboard{}, err
		}
		dashboard.RelationshipCount, err = s.CountAssetRelationships(ctx, RelationshipFilter{
			AccountID: baseAssetFilter.AccountID,
			Provider:  baseAssetFilter.Provider,
			Region:    baseAssetFilter.Region,
		})
		if err != nil {
			return model.Dashboard{}, err
		}
	}

	dashboard.CriticalFindingCount, err = s.CountFindings(ctx, FindingFilter{
		AccountID: baseFindingFilter.AccountID,
		Provider:  baseFindingFilter.Provider,
		Region:    baseFindingFilter.Region,
		Severity:  model.SeverityCritical,
	})
	if err != nil {
		return model.Dashboard{}, err
	}
	dashboard.HighFindingCount, err = s.CountFindings(ctx, FindingFilter{
		AccountID: baseFindingFilter.AccountID,
		Provider:  baseFindingFilter.Provider,
		Region:    baseFindingFilter.Region,
		Severity:  model.SeverityHigh,
	})
	if err != nil {
		return model.Dashboard{}, err
	}
	dashboard.RuleCount, err = s.countRules(ctx, RuleFilter{
		AccountID: baseFindingFilter.AccountID,
		Provider:  baseFindingFilter.Provider,
		Region:    baseFindingFilter.Region,
	})
	if err != nil {
		return model.Dashboard{}, err
	}
	dashboard.AccountCount, err = s.countAccounts(ctx, filter.AccountID)
	if err != nil {
		return model.Dashboard{}, err
	}

	dashboard.StatusCounts, err = s.findingGroupCounts(ctx, "f.status", baseFindingFilter)
	if err != nil {
		return model.Dashboard{}, err
	}
	dashboard.SeverityCounts, err = s.findingGroupCounts(ctx, "f.severity", baseFindingFilter)
	if err != nil {
		return model.Dashboard{}, err
	}
	dashboard.ProviderCounts, err = s.assetFacetCounts(ctx, "a.provider", baseAssetFilter)
	if err != nil {
		return model.Dashboard{}, err
	}
	dashboard.RegionCounts, err = s.assetFacetCounts(ctx, "a.region", baseAssetFilter)
	if err != nil {
		return model.Dashboard{}, err
	}
	dashboard.ResourceTypeCounts, err = s.assetFacetCounts(ctx, "a.resource_type", baseAssetFilter)
	if err != nil {
		return model.Dashboard{}, err
	}

	recentFindings, err := s.ListFindingViews(ctx, FindingFilter{
		AccountID: baseFindingFilter.AccountID,
		Provider:  baseFindingFilter.Provider,
		Region:    baseFindingFilter.Region,
		Sort:      "-last_seen_at",
		Limit:     5,
	})
	if err != nil {
		return model.Dashboard{}, err
	}
	dashboard.RecentFindings = recentFindings.Findings

	recentAssets, err := s.ListAssetViews(ctx, AssetFilter{
		AccountID: baseAssetFilter.AccountID,
		Provider:  baseAssetFilter.Provider,
		Region:    baseAssetFilter.Region,
		Sort:      "-last_seen_at",
		Limit:     5,
	})
	if err != nil {
		return model.Dashboard{}, err
	}
	dashboard.RecentAssets = recentAssets.Assets

	return dashboard, nil
}

func (s *SQLiteStore) GetFacets(ctx context.Context, filter FacetFilter) (model.FacetSet, error) {
	assetFilter := AssetFilter{
		AccountID:    filter.AccountID,
		Provider:     filter.Provider,
		ResourceType: filter.ResourceType,
		Region:       filter.Region,
		Q:            filter.Q,
	}
	findingFilter := FindingFilter{
		AccountID:    filter.AccountID,
		Provider:     filter.Provider,
		ResourceType: filter.ResourceType,
		Region:       filter.Region,
		Severity:     filter.Severity,
		Status:       filter.Status,
		Q:            filter.Q,
	}

	accounts, err := s.assetFacetCounts(ctx, "a.account_id", assetFilter)
	if err != nil {
		return model.FacetSet{}, err
	}
	providers, err := s.assetFacetCounts(ctx, "a.provider", assetFilter)
	if err != nil {
		return model.FacetSet{}, err
	}
	regions, err := s.assetFacetCounts(ctx, "a.region", assetFilter)
	if err != nil {
		return model.FacetSet{}, err
	}
	resourceTypes, err := s.assetFacetCounts(ctx, "a.resource_type", assetFilter)
	if err != nil {
		return model.FacetSet{}, err
	}
	severities, err := s.findingFacetCounts(ctx, "f.severity", findingFilter)
	if err != nil {
		return model.FacetSet{}, err
	}
	statuses, err := s.findingFacetCounts(ctx, "f.status", findingFilter)
	if err != nil {
		return model.FacetSet{}, err
	}
	rules, err := s.findingFacetCounts(ctx, "f.rule_id", findingFilter)
	if err != nil {
		return model.FacetSet{}, err
	}

	return model.FacetSet{
		Accounts:      accounts,
		Providers:     providers,
		Regions:       regions,
		ResourceTypes: resourceTypes,
		AssetTypes:    resourceTypes,
		Severities:    severities,
		Statuses:      statuses,
		Rules:         rules,
	}, nil
}

func (s *SQLiteStore) GetGraph(ctx context.Context, filter GraphFilter) (model.GraphResponse, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	assetFilter := AssetFilter{
		AccountID:    filter.AccountID,
		Provider:     filter.Provider,
		ResourceType: filter.ResourceType,
		ResourceID:   filter.ResourceID,
		Region:       filter.Region,
		Q:            filter.Q,
		Limit:        limit,
		Offset:       filter.Offset,
	}
	if strings.TrimSpace(filter.AssetID) != "" {
		asset, err := s.GetAssetView(ctx, filter.AssetID)
		if err != nil {
			return model.GraphResponse{}, err
		}
		return s.graphForAssets(ctx, []model.AssetView{asset}, filter)
	}

	assets, err := s.ListAssetViews(ctx, assetFilter)
	if err != nil {
		return model.GraphResponse{}, err
	}
	return s.graphForAssets(ctx, assets.Assets, filter)
}

func (s *SQLiteStore) ListRules(ctx context.Context, filter RuleFilter) (model.RuleList, error) {
	total, err := s.countRules(ctx, filter)
	if err != nil {
		return model.RuleList{}, err
	}

	var (
		query strings.Builder
		args  []any
	)
	query.WriteString(`
SELECT f.rule_id,
    COALESCE(NULLIF(MAX(f.title), ''), f.rule_id) AS title,
    MAX(CASE f.severity
        WHEN 'critical' THEN 5
        WHEN 'high' THEN 4
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 2
        WHEN 'info' THEN 1
        ELSE 0
    END) AS severity_rank,
    MAX(f.remediation) AS remediation,
    MIN(f.first_seen_at) AS first_seen_at,
    MAX(f.last_seen_at) AS last_seen_at,
    COUNT(*) AS finding_count,
    SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS open_finding_count,
    COUNT(DISTINCT f.asset_id) AS affected_asset_count
FROM findings f
JOIN assets a ON a.id = f.asset_id
`)
	clause, whereArgs := ruleWhereClause("f", "a", filter)
	query.WriteString(clause)
	args = append(args, whereArgs...)
	query.WriteString(" GROUP BY f.rule_id")
	query.WriteString(ruleOrderBy(filter.Sort))
	appendLimit(&query, &args, filter.Limit, filter.Offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return model.RuleList{}, fmt.Errorf("list rules: %w", err)
	}

	rules := make([]model.RuleView, 0)
	for rows.Next() {
		ruleView, err := scanRuleView(rows)
		if err != nil {
			_ = rows.Close()
			return model.RuleList{}, err
		}
		rules = append(rules, ruleView)
	}
	if err := rows.Close(); err != nil {
		return model.RuleList{}, fmt.Errorf("close rules: %w", err)
	}
	if err := rows.Err(); err != nil {
		return model.RuleList{}, fmt.Errorf("iterate rules: %w", err)
	}

	for i := range rules {
		rules[i].SeverityCounts, err = s.ruleSeverityCounts(ctx, rules[i].RuleID, filter)
		if err != nil {
			return model.RuleList{}, err
		}
		rules[i].StatusCounts, err = s.ruleStatusCounts(ctx, rules[i].RuleID, filter)
		if err != nil {
			return model.RuleList{}, err
		}
	}

	return model.RuleList{
		Rules:  rules,
		Total:  total,
		Offset: filter.Offset,
		Limit:  filter.Limit,
	}, nil
}

func (s *SQLiteStore) GetRule(ctx context.Context, id string) (model.RuleView, error) {
	if strings.TrimSpace(id) == "" {
		return model.RuleView{}, errors.New("rule id is required")
	}
	rules, err := s.ListRules(ctx, RuleFilter{
		RuleID: strings.TrimSpace(id),
		Limit:  1,
	})
	if err != nil {
		return model.RuleView{}, err
	}
	if len(rules.Rules) == 0 {
		return model.RuleView{}, sql.ErrNoRows
	}
	ruleView := rules.Rules[0]
	findings, err := s.ListFindingViews(ctx, FindingFilter{
		RuleID: strings.TrimSpace(id),
		Sort:   "-last_seen_at",
		Limit:  100,
	})
	if err != nil {
		return model.RuleView{}, err
	}
	ruleView.Findings = findings.Findings
	return ruleView, nil
}

func (s *SQLiteStore) configure(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("enable sqlite foreign keys: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return fmt.Errorf("set sqlite busy timeout: %w", err)
	}
	return nil
}

func appendLimit(query *strings.Builder, args *[]any, limit int, offset int) {
	if limit <= 0 {
		if offset > 0 {
			query.WriteString(" LIMIT -1 OFFSET ?")
			*args = append(*args, offset)
		}
		return
	}
	query.WriteString(" LIMIT ?")
	*args = append(*args, limit)
	if offset > 0 {
		query.WriteString(" OFFSET ?")
		*args = append(*args, offset)
	}
}

func scanRunWhereClause(alias string, filter ScanRunFilter) (string, []any) {
	var query strings.Builder
	var args []any
	query.WriteString(" WHERE 1 = 1")
	appendEqual(&query, &args, qcol(alias, "account_id"), filter.AccountID)
	appendEqual(&query, &args, qcol(alias, "provider"), filter.Provider)
	appendEqual(&query, &args, qcol(alias, "status"), filter.Status)
	appendLikeAny(&query, &args, []string{
		qcol(alias, "id"),
		qcol(alias, "account_id"),
		qcol(alias, "provider"),
		qcol(alias, "status"),
		qcol(alias, "summary_json"),
	}, filter.Q)
	return query.String(), args
}

func scanTaskRunWhereClause(alias string, filter ScanTaskRunFilter) (string, []any) {
	var query strings.Builder
	var args []any
	query.WriteString(" WHERE 1 = 1")
	appendEqual(&query, &args, qcol(alias, "scan_run_id"), filter.ScanRunID)
	appendEqual(&query, &args, qcol(alias, "account_id"), filter.AccountID)
	appendEqual(&query, &args, qcol(alias, "provider"), filter.Provider)
	appendEqual(&query, &args, qcol(alias, "resource_type"), filter.ResourceType)
	appendEqual(&query, &args, qcol(alias, "region"), filter.Region)
	appendEqual(&query, &args, qcol(alias, "status"), filter.Status)
	appendEqual(&query, &args, qcol(alias, "category"), filter.Category)
	appendLikeAny(&query, &args, []string{
		qcol(alias, "scope"),
		qcol(alias, "resource_type"),
		qcol(alias, "region"),
		qcol(alias, "status"),
		qcol(alias, "category"),
		qcol(alias, "message"),
	}, filter.Q)
	return query.String(), args
}

func assetWhereClause(alias string, filter AssetFilter) (string, []any) {
	var query strings.Builder
	var args []any
	query.WriteString(" WHERE 1 = 1")
	appendEqual(&query, &args, qcol(alias, "account_id"), filter.AccountID)
	appendEqual(&query, &args, qcol(alias, "provider"), filter.Provider)
	appendEqual(&query, &args, qcol(alias, "resource_type"), filter.ResourceType)
	appendEqual(&query, &args, qcol(alias, "resource_id"), filter.ResourceID)
	appendEqual(&query, &args, qcol(alias, "region"), filter.Region)
	appendLikeAny(&query, &args, []string{
		qcol(alias, "resource_type"),
		qcol(alias, "resource_id"),
		qcol(alias, "region"),
		qcol(alias, "name"),
		qcol(alias, "provider"),
		qcol(alias, "properties_json"),
	}, filter.Q)
	return query.String(), args
}

func relationshipWhereClause(relationshipAlias string, assetAlias string, filter RelationshipFilter) (string, []any) {
	var query strings.Builder
	var args []any
	query.WriteString(" WHERE 1 = 1")
	appendEqual(&query, &args, qcol(relationshipAlias, "account_id"), filter.AccountID)
	appendEqual(&query, &args, qcol(relationshipAlias, "provider"), filter.Provider)
	appendEqual(&query, &args, qcol(relationshipAlias, "source_asset_id"), filter.SourceAssetID)
	appendEqual(&query, &args, qcol(relationshipAlias, "source_resource_id"), filter.SourceResourceID)
	appendEqual(&query, &args, qcol(relationshipAlias, "target_resource_id"), filter.TargetResourceID)
	appendEqual(&query, &args, qcol(relationshipAlias, "source_resource_type"), filter.ResourceType)
	appendEqual(&query, &args, qcol(relationshipAlias, "relationship_type"), filter.RelationshipType)
	if strings.TrimSpace(assetAlias) != "" {
		appendEqual(&query, &args, qcol(assetAlias, "region"), filter.Region)
	}

	qColumns := []string{
		qcol(relationshipAlias, "source_resource_type"),
		qcol(relationshipAlias, "source_resource_id"),
		qcol(relationshipAlias, "target_resource_id"),
		qcol(relationshipAlias, "relationship_type"),
		qcol(relationshipAlias, "properties_json"),
	}
	if strings.TrimSpace(assetAlias) != "" {
		qColumns = append(qColumns,
			qcol(assetAlias, "resource_type"),
			qcol(assetAlias, "resource_id"),
			qcol(assetAlias, "region"),
			qcol(assetAlias, "name"),
		)
	}
	appendLikeAny(&query, &args, qColumns, filter.Q)
	return query.String(), args
}

func findingWhereClause(findingAlias string, assetAlias string, filter FindingFilter) (string, []any) {
	var query strings.Builder
	var args []any
	query.WriteString(" WHERE 1 = 1")
	appendEqual(&query, &args, qcol(findingAlias, "account_id"), filter.AccountID)
	appendEqual(&query, &args, qcol(findingAlias, "scan_run_id"), filter.ScanRunID)
	appendEqual(&query, &args, qcol(findingAlias, "asset_id"), filter.AssetID)
	appendEqual(&query, &args, qcol(findingAlias, "rule_id"), filter.RuleID)
	appendEqual(&query, &args, qcol(findingAlias, "severity"), filter.Severity)
	appendEqual(&query, &args, qcol(findingAlias, "status"), filter.Status)
	if strings.TrimSpace(assetAlias) != "" {
		appendEqual(&query, &args, qcol(assetAlias, "provider"), filter.Provider)
		appendEqual(&query, &args, qcol(assetAlias, "resource_type"), filter.ResourceType)
		appendEqual(&query, &args, qcol(assetAlias, "region"), filter.Region)
	}

	qColumns := []string{
		qcol(findingAlias, "rule_id"),
		qcol(findingAlias, "title"),
		qcol(findingAlias, "severity"),
		qcol(findingAlias, "status"),
		qcol(findingAlias, "message"),
		qcol(findingAlias, "remediation"),
		qcol(findingAlias, "evidence_json"),
	}
	if strings.TrimSpace(assetAlias) != "" {
		qColumns = append(qColumns,
			qcol(assetAlias, "provider"),
			qcol(assetAlias, "resource_type"),
			qcol(assetAlias, "resource_id"),
			qcol(assetAlias, "region"),
			qcol(assetAlias, "name"),
		)
	}
	appendLikeAny(&query, &args, qColumns, filter.Q)
	return query.String(), args
}

func ruleWhereClause(findingAlias string, assetAlias string, filter RuleFilter) (string, []any) {
	var query strings.Builder
	var args []any
	query.WriteString(" WHERE 1 = 1")
	appendEqual(&query, &args, qcol(findingAlias, "account_id"), filter.AccountID)
	appendEqual(&query, &args, qcol(findingAlias, "rule_id"), filter.RuleID)
	appendEqual(&query, &args, qcol(findingAlias, "severity"), filter.Severity)
	appendEqual(&query, &args, qcol(findingAlias, "status"), filter.Status)
	appendEqual(&query, &args, qcol(assetAlias, "provider"), filter.Provider)
	appendEqual(&query, &args, qcol(assetAlias, "resource_type"), filter.ResourceType)
	appendEqual(&query, &args, qcol(assetAlias, "region"), filter.Region)
	appendLikeAny(&query, &args, []string{
		qcol(findingAlias, "rule_id"),
		qcol(findingAlias, "title"),
		qcol(findingAlias, "severity"),
		qcol(findingAlias, "status"),
		qcol(findingAlias, "message"),
		qcol(findingAlias, "remediation"),
		qcol(assetAlias, "provider"),
		qcol(assetAlias, "resource_type"),
		qcol(assetAlias, "region"),
	}, filter.Q)
	return query.String(), args
}

func appendEqual(query *strings.Builder, args *[]any, column string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	query.WriteString(" AND ")
	query.WriteString(column)
	query.WriteString(" = ?")
	*args = append(*args, value)
}

func appendLikeAny(query *strings.Builder, args *[]any, columns []string, value string) {
	value = strings.TrimSpace(value)
	if value == "" || len(columns) == 0 {
		return
	}
	pattern := "%" + strings.ToLower(value) + "%"
	query.WriteString(" AND (")
	for i, column := range columns {
		if i > 0 {
			query.WriteString(" OR ")
		}
		query.WriteString("LOWER(")
		query.WriteString(column)
		query.WriteString(") LIKE ?")
		*args = append(*args, pattern)
	}
	query.WriteString(")")
}

func qcol(alias string, column string) string {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return column
	}
	return alias + "." + column
}

type sortOption struct {
	Asc  string
	Desc string
}

func scanRunOrderBy(sort string) string {
	columns := map[string]sortOption{
		"started_at":  {Asc: "started_at ASC, id ASC", Desc: "started_at DESC, id ASC"},
		"finished_at": {Asc: "finished_at ASC, id ASC", Desc: "finished_at DESC, id ASC"},
		"updated_at":  {Asc: "updated_at ASC, id ASC", Desc: "updated_at DESC, id ASC"},
		"status":      {Asc: "status ASC, started_at DESC", Desc: "status DESC, started_at DESC"},
		"provider":    {Asc: "provider ASC, started_at DESC", Desc: "provider DESC, started_at DESC"},
	}
	return orderBy(sort, columns, "started_at DESC, id ASC")
}

func scanTaskRunOrderBy(sort string) string {
	columns := map[string]sortOption{
		"started_at":    {Asc: "started_at ASC, id ASC", Desc: "started_at DESC, id ASC"},
		"duration_ms":   {Asc: "duration_ms ASC, id ASC", Desc: "duration_ms DESC, id ASC"},
		"resource_type": {Asc: "resource_type ASC, region ASC", Desc: "resource_type DESC, region DESC"},
		"status":        {Asc: "status ASC, started_at DESC", Desc: "status DESC, started_at DESC"},
	}
	return orderBy(sort, columns, "started_at DESC, id ASC")
}

func assetOrderBy(sort string, alias string) string {
	columns := map[string]sortOption{
		"last_seen_at":  {Asc: qcol(alias, "last_seen_at") + " ASC, " + qcol(alias, "id") + " ASC", Desc: qcol(alias, "last_seen_at") + " DESC, " + qcol(alias, "id") + " ASC"},
		"first_seen_at": {Asc: qcol(alias, "first_seen_at") + " ASC, " + qcol(alias, "id") + " ASC", Desc: qcol(alias, "first_seen_at") + " DESC, " + qcol(alias, "id") + " ASC"},
		"updated_at":    {Asc: qcol(alias, "updated_at") + " ASC, " + qcol(alias, "id") + " ASC", Desc: qcol(alias, "updated_at") + " DESC, " + qcol(alias, "id") + " ASC"},
		"name":          {Asc: qcol(alias, "name") + " ASC, " + qcol(alias, "id") + " ASC", Desc: qcol(alias, "name") + " DESC, " + qcol(alias, "id") + " ASC"},
		"resource_type": {Asc: qcol(alias, "resource_type") + " ASC, " + qcol(alias, "resource_id") + " ASC", Desc: qcol(alias, "resource_type") + " DESC, " + qcol(alias, "resource_id") + " ASC"},
		"resource_id":   {Asc: qcol(alias, "resource_id") + " ASC", Desc: qcol(alias, "resource_id") + " DESC"},
		"region":        {Asc: qcol(alias, "region") + " ASC, " + qcol(alias, "resource_id") + " ASC", Desc: qcol(alias, "region") + " DESC, " + qcol(alias, "resource_id") + " ASC"},
		"provider":      {Asc: qcol(alias, "provider") + " ASC, " + qcol(alias, "resource_id") + " ASC", Desc: qcol(alias, "provider") + " DESC, " + qcol(alias, "resource_id") + " ASC"},
	}
	return orderBy(sort, columns, qcol(alias, "last_seen_at")+" DESC, "+qcol(alias, "resource_type")+" ASC, "+qcol(alias, "resource_id")+" ASC")
}

func assetViewOrderBy(sort string) string {
	columns := map[string]sortOption{
		"finding_count":          {Asc: "finding_count ASC, a.last_seen_at DESC", Desc: "finding_count DESC, a.last_seen_at DESC"},
		"open_finding_count":     {Asc: "open_finding_count ASC, a.last_seen_at DESC", Desc: "open_finding_count DESC, a.last_seen_at DESC"},
		"critical_finding_count": {Asc: "critical_finding_count ASC, a.last_seen_at DESC", Desc: "critical_finding_count DESC, a.last_seen_at DESC"},
		"high_finding_count":     {Asc: "high_finding_count ASC, a.last_seen_at DESC", Desc: "high_finding_count DESC, a.last_seen_at DESC"},
		"last_seen_at":           {Asc: "a.last_seen_at ASC, a.id ASC", Desc: "a.last_seen_at DESC, a.id ASC"},
		"first_seen_at":          {Asc: "a.first_seen_at ASC, a.id ASC", Desc: "a.first_seen_at DESC, a.id ASC"},
		"updated_at":             {Asc: "a.updated_at ASC, a.id ASC", Desc: "a.updated_at DESC, a.id ASC"},
		"name":                   {Asc: "a.name ASC, a.id ASC", Desc: "a.name DESC, a.id ASC"},
		"resource_type":          {Asc: "a.resource_type ASC, a.resource_id ASC", Desc: "a.resource_type DESC, a.resource_id ASC"},
		"resource_id":            {Asc: "a.resource_id ASC", Desc: "a.resource_id DESC"},
		"region":                 {Asc: "a.region ASC, a.resource_id ASC", Desc: "a.region DESC, a.resource_id ASC"},
	}
	return orderBy(sort, columns, "a.last_seen_at DESC, a.resource_type ASC, a.resource_id ASC")
}

func relationshipOrderBy(sort string, alias string) string {
	columns := map[string]sortOption{
		"last_seen_at":       {Asc: qcol(alias, "last_seen_at") + " ASC, " + qcol(alias, "id") + " ASC", Desc: qcol(alias, "last_seen_at") + " DESC, " + qcol(alias, "id") + " ASC"},
		"relationship_type":  {Asc: qcol(alias, "relationship_type") + " ASC, " + qcol(alias, "source_resource_id") + " ASC", Desc: qcol(alias, "relationship_type") + " DESC, " + qcol(alias, "source_resource_id") + " ASC"},
		"source_resource_id": {Asc: qcol(alias, "source_resource_id") + " ASC", Desc: qcol(alias, "source_resource_id") + " DESC"},
		"target_resource_id": {Asc: qcol(alias, "target_resource_id") + " ASC", Desc: qcol(alias, "target_resource_id") + " DESC"},
	}
	return orderBy(sort, columns, qcol(alias, "last_seen_at")+" DESC, "+qcol(alias, "source_resource_id")+" ASC, "+qcol(alias, "relationship_type")+" ASC")
}

func findingOrderBy(sort string, findingAlias string, assetAlias string) string {
	severityRank := severityRankSQL(qcol(findingAlias, "severity"))
	columns := map[string]sortOption{
		"last_seen_at":  {Asc: qcol(findingAlias, "last_seen_at") + " ASC, " + qcol(findingAlias, "id") + " ASC", Desc: qcol(findingAlias, "last_seen_at") + " DESC, " + qcol(findingAlias, "id") + " ASC"},
		"first_seen_at": {Asc: qcol(findingAlias, "first_seen_at") + " ASC, " + qcol(findingAlias, "id") + " ASC", Desc: qcol(findingAlias, "first_seen_at") + " DESC, " + qcol(findingAlias, "id") + " ASC"},
		"updated_at":    {Asc: qcol(findingAlias, "updated_at") + " ASC, " + qcol(findingAlias, "id") + " ASC", Desc: qcol(findingAlias, "updated_at") + " DESC, " + qcol(findingAlias, "id") + " ASC"},
		"severity":      {Asc: severityRank + " ASC, " + qcol(findingAlias, "last_seen_at") + " DESC", Desc: severityRank + " DESC, " + qcol(findingAlias, "last_seen_at") + " DESC"},
		"status":        {Asc: qcol(findingAlias, "status") + " ASC, " + qcol(findingAlias, "last_seen_at") + " DESC", Desc: qcol(findingAlias, "status") + " DESC, " + qcol(findingAlias, "last_seen_at") + " DESC"},
		"rule_id":       {Asc: qcol(findingAlias, "rule_id") + " ASC, " + qcol(findingAlias, "last_seen_at") + " DESC", Desc: qcol(findingAlias, "rule_id") + " DESC, " + qcol(findingAlias, "last_seen_at") + " DESC"},
		"title":         {Asc: qcol(findingAlias, "title") + " ASC, " + qcol(findingAlias, "last_seen_at") + " DESC", Desc: qcol(findingAlias, "title") + " DESC, " + qcol(findingAlias, "last_seen_at") + " DESC"},
		"resource_type": {Asc: qcol(assetAlias, "resource_type") + " ASC, " + qcol(findingAlias, "last_seen_at") + " DESC", Desc: qcol(assetAlias, "resource_type") + " DESC, " + qcol(findingAlias, "last_seen_at") + " DESC"},
		"region":        {Asc: qcol(assetAlias, "region") + " ASC, " + qcol(findingAlias, "last_seen_at") + " DESC", Desc: qcol(assetAlias, "region") + " DESC, " + qcol(findingAlias, "last_seen_at") + " DESC"},
	}
	return orderBy(sort, columns, qcol(findingAlias, "last_seen_at")+" DESC, "+qcol(findingAlias, "id")+" ASC")
}

func ruleOrderBy(sort string) string {
	columns := map[string]sortOption{
		"last_seen_at":         {Asc: "last_seen_at ASC, rule_id ASC", Desc: "last_seen_at DESC, rule_id ASC"},
		"first_seen_at":        {Asc: "first_seen_at ASC, rule_id ASC", Desc: "first_seen_at DESC, rule_id ASC"},
		"severity":             {Asc: "severity_rank ASC, last_seen_at DESC", Desc: "severity_rank DESC, last_seen_at DESC"},
		"finding_count":        {Asc: "finding_count ASC, last_seen_at DESC", Desc: "finding_count DESC, last_seen_at DESC"},
		"open_finding_count":   {Asc: "open_finding_count ASC, last_seen_at DESC", Desc: "open_finding_count DESC, last_seen_at DESC"},
		"affected_asset_count": {Asc: "affected_asset_count ASC, last_seen_at DESC", Desc: "affected_asset_count DESC, last_seen_at DESC"},
		"title":                {Asc: "title ASC, rule_id ASC", Desc: "title DESC, rule_id ASC"},
		"rule_id":              {Asc: "rule_id ASC", Desc: "rule_id DESC"},
	}
	return orderBy(sort, columns, "open_finding_count DESC, severity_rank DESC, last_seen_at DESC, rule_id ASC")
}

func orderBy(raw string, columns map[string]sortOption, fallback string) string {
	field, desc, ok := parseSort(raw)
	if !ok {
		return " ORDER BY " + fallback
	}
	option, ok := columns[field]
	if !ok {
		return " ORDER BY " + fallback
	}
	if desc {
		return " ORDER BY " + option.Desc
	}
	return " ORDER BY " + option.Asc
}

func parseSort(raw string) (string, bool, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", false, false
	}
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, " ", "_")

	desc := false
	if strings.HasPrefix(value, "-") {
		desc = true
		value = strings.TrimPrefix(value, "-")
	}
	if strings.HasPrefix(value, "+") {
		value = strings.TrimPrefix(value, "+")
	}
	switch {
	case strings.HasSuffix(value, "_desc"):
		desc = true
		value = strings.TrimSuffix(value, "_desc")
	case strings.HasSuffix(value, "_asc"):
		value = strings.TrimSuffix(value, "_asc")
	}
	if value == "" {
		return "", false, false
	}
	return value, desc, true
}

func severityRankSQL(column string) string {
	return "CASE " + column + " WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"
}

func accountWhereClause(accountID string) (string, []any) {
	if strings.TrimSpace(accountID) == "" {
		return "", nil
	}
	return " WHERE account_id = ?", []any{strings.TrimSpace(accountID)}
}

func scanDeltaFromSummary(raw json.RawMessage) model.ScanDelta {
	var payload struct {
		AddedAssets   int `json:"added_assets"`
		UpdatedAssets int `json:"updated_assets"`
		MissingAssets int `json:"missing_assets"`
		SeenAssets    int `json:"seen_assets"`
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return model.ScanDelta{}
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return model.ScanDelta{}
	}
	return model.ScanDelta{
		AddedAssets:   payload.AddedAssets,
		UpdatedAssets: payload.UpdatedAssets,
		MissingAssets: payload.MissingAssets,
		SeenAssets:    payload.SeenAssets,
	}
}

func (s *SQLiteStore) assetFacetCounts(ctx context.Context, expression string, filter AssetFilter) ([]model.FacetValue, error) {
	clause, args := assetWhereClause("a", filter)
	rows, err := s.db.QueryContext(ctx, `
SELECT `+expression+` AS value, COUNT(*) AS count
FROM assets a
`+clause+`
GROUP BY `+expression+`
ORDER BY count DESC, value ASC
`, args...)
	if err != nil {
		return nil, fmt.Errorf("asset facet counts: %w", err)
	}
	defer rows.Close()
	return scanFacetValues(rows)
}

func (s *SQLiteStore) findingFacetCounts(ctx context.Context, expression string, filter FindingFilter) ([]model.FacetValue, error) {
	clause, args := findingWhereClause("f", "a", filter)
	rows, err := s.db.QueryContext(ctx, `
SELECT `+expression+` AS value, COUNT(*) AS count
FROM findings f
JOIN assets a ON a.id = f.asset_id
`+clause+`
GROUP BY `+expression+`
ORDER BY count DESC, value ASC
`, args...)
	if err != nil {
		return nil, fmt.Errorf("finding facet counts: %w", err)
	}
	defer rows.Close()
	return scanFacetValues(rows)
}

func (s *SQLiteStore) findingGroupCounts(ctx context.Context, expression string, filter FindingFilter) (map[string]int, error) {
	clause, args := findingWhereClause("f", "a", filter)
	rows, err := s.db.QueryContext(ctx, `
SELECT `+expression+` AS value, COUNT(*) AS count
FROM findings f
JOIN assets a ON a.id = f.asset_id
`+clause+`
GROUP BY `+expression+`
`, args...)
	if err != nil {
		return nil, fmt.Errorf("finding group counts: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var value string
		var count int
		if err := rows.Scan(&value, &count); err != nil {
			return nil, fmt.Errorf("scan finding group count: %w", err)
		}
		counts[value] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding group counts: %w", err)
	}
	return counts, nil
}

func scanFacetValues(rows *sql.Rows) ([]model.FacetValue, error) {
	values := make([]model.FacetValue, 0)
	for rows.Next() {
		var value string
		var count int
		if err := rows.Scan(&value, &count); err != nil {
			return nil, fmt.Errorf("scan facet value: %w", err)
		}
		values = append(values, model.FacetValue{
			Value: value,
			Label: facetLabel(value),
			Count: count,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate facet values: %w", err)
	}
	return values, nil
}

func facetLabel(value string) string {
	if strings.TrimSpace(value) == "" {
		return "Unspecified"
	}
	return value
}

func (s *SQLiteStore) findingSeverityCounts(ctx context.Context, assetID string, ruleID string) (map[string]int, error) {
	filter := FindingFilter{
		AssetID: strings.TrimSpace(assetID),
		RuleID:  strings.TrimSpace(ruleID),
	}
	return s.findingGroupCounts(ctx, "f.severity", filter)
}

func (s *SQLiteStore) ruleSeverityCounts(ctx context.Context, ruleID string, filter RuleFilter) (map[string]int, error) {
	findingFilter := FindingFilter{
		AccountID:    filter.AccountID,
		Provider:     filter.Provider,
		ResourceType: filter.ResourceType,
		Region:       filter.Region,
		RuleID:       ruleID,
		Severity:     filter.Severity,
		Status:       filter.Status,
		Q:            filter.Q,
	}
	return s.findingGroupCounts(ctx, "f.severity", findingFilter)
}

func (s *SQLiteStore) ruleStatusCounts(ctx context.Context, ruleID string, filter RuleFilter) (map[string]int, error) {
	findingFilter := FindingFilter{
		AccountID:    filter.AccountID,
		Provider:     filter.Provider,
		ResourceType: filter.ResourceType,
		Region:       filter.Region,
		RuleID:       ruleID,
		Severity:     filter.Severity,
		Status:       filter.Status,
		Q:            filter.Q,
	}
	return s.findingGroupCounts(ctx, "f.status", findingFilter)
}

func (s *SQLiteStore) countRules(ctx context.Context, filter RuleFilter) (int, error) {
	clause, args := ruleWhereClause("f", "a", filter)
	var count int
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT f.rule_id)
FROM findings f
JOIN assets a ON a.id = f.asset_id
`+clause, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count rules: %w", err)
	}
	return count, nil
}

func (s *SQLiteStore) countAccounts(ctx context.Context, accountID string) (int, error) {
	accountID = strings.TrimSpace(accountID)
	var count int
	if accountID == "" {
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM accounts").Scan(&count); err != nil {
			return 0, fmt.Errorf("count accounts: %w", err)
		}
		return count, nil
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM accounts WHERE id = ?", accountID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count accounts: %w", err)
	}
	return count, nil
}

func (s *SQLiteStore) graphForAssets(ctx context.Context, assets []model.AssetView, filter GraphFilter) (model.GraphResponse, error) {
	nodesByID := map[string]model.GraphNode{}
	sourceIDs := map[string]bool{}
	for _, asset := range assets {
		nodesByID[asset.ID] = graphNodeFromAsset(asset)
		sourceIDs[asset.ID] = true
	}

	relationshipLimit := filter.Limit
	if relationshipLimit <= 0 {
		relationshipLimit = 500
	} else {
		relationshipLimit *= 5
	}
	relationships, err := s.ListAssetRelationships(ctx, RelationshipFilter{
		AccountID: filter.AccountID,
		Provider:  filter.Provider,
		Region:    filter.Region,
		Limit:     relationshipLimit,
	})
	if err != nil {
		return model.GraphResponse{}, err
	}

	edges := make([]model.GraphEdge, 0)
	for _, relationship := range relationships {
		if len(sourceIDs) > 0 && !sourceIDs[relationship.SourceAssetID] {
			continue
		}
		targetID := "resource:" + relationship.TargetResourceID
		if target, ok, err := s.assetViewByResourceID(ctx, relationship.AccountID, relationship.TargetResourceID); err != nil {
			return model.GraphResponse{}, err
		} else if ok {
			targetID = target.ID
			if _, exists := nodesByID[target.ID]; !exists {
				nodesByID[target.ID] = graphNodeFromAsset(target)
			}
		} else if _, exists := nodesByID[targetID]; !exists {
			nodesByID[targetID] = model.GraphNode{
				ID:         targetID,
				Label:      relationship.TargetResourceID,
				Kind:       "resource_ref",
				AccountID:  relationship.AccountID,
				Provider:   relationship.Provider,
				ResourceID: relationship.TargetResourceID,
			}
		}

		edges = append(edges, model.GraphEdge{
			ID:               relationship.ID,
			SourceID:         relationship.SourceAssetID,
			TargetID:         targetID,
			Source:           relationship.SourceAssetID,
			Target:           targetID,
			RelationshipType: relationship.RelationshipType,
			Label:            relationship.RelationshipType,
			Properties:       relationship.Properties,
		})
	}

	nodes := make([]model.GraphNode, 0, len(nodesByID))
	for _, node := range nodesByID {
		nodes = append(nodes, node)
	}
	return model.GraphResponse{Nodes: nodes, Edges: edges}, nil
}

func graphNodeFromAsset(asset model.AssetView) model.GraphNode {
	label := strings.TrimSpace(asset.Name)
	if label == "" {
		label = asset.ResourceID
	}
	severity := highestSeverity(asset.SeverityCounts)
	if severity == "" {
		switch {
		case asset.CriticalFindingCount > 0:
			severity = model.SeverityCritical
		case asset.HighFindingCount > 0:
			severity = model.SeverityHigh
		}
	}
	return model.GraphNode{
		ID:               asset.ID,
		Label:            label,
		Kind:             "asset",
		AccountID:        asset.AccountID,
		Provider:         asset.Provider,
		ResourceType:     asset.ResourceType,
		ResourceID:       asset.ResourceID,
		Region:           asset.Region,
		Severity:         severity,
		FindingCount:     asset.FindingCount,
		OpenFindingCount: asset.OpenFindingCount,
		Properties:       asset.Properties,
	}
}

func highestSeverity(counts map[string]int) string {
	for _, severity := range []string{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
		model.SeverityUnknown,
	} {
		if counts[severity] > 0 {
			return severity
		}
	}
	return ""
}

func (s *SQLiteStore) assetViewByResourceID(ctx context.Context, accountID string, resourceID string) (model.AssetView, bool, error) {
	if strings.TrimSpace(resourceID) == "" {
		return model.AssetView{}, false, nil
	}
	filter := AssetFilter{
		AccountID:  strings.TrimSpace(accountID),
		ResourceID: strings.TrimSpace(resourceID),
		Limit:      1,
	}
	assets, err := s.ListAssetViews(ctx, filter)
	if err != nil {
		return model.AssetView{}, false, err
	}
	if len(assets.Assets) == 0 {
		return model.AssetView{}, false, nil
	}
	asset := assets.Assets[0]
	asset.SeverityCounts, err = s.findingSeverityCounts(ctx, asset.ID, "")
	if err != nil {
		return model.AssetView{}, false, err
	}
	return asset, true, nil
}

func cloneIntMap(input map[string]int) map[string]int {
	output := make(map[string]int, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAccount(row rowScanner) (model.Account, error) {
	var account model.Account
	var metadata string
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&account.ID,
		&account.Provider,
		&account.Name,
		&account.ExternalID,
		&metadata,
		&createdAt,
		&updatedAt,
	); err != nil {
		return model.Account{}, fmt.Errorf("scan account: %w", err)
	}

	var err error
	account.Metadata = json.RawMessage(metadata)
	account.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.Account{}, err
	}
	account.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.Account{}, err
	}
	return account, nil
}

func scanScanRun(row rowScanner) (model.ScanRun, error) {
	var run model.ScanRun
	var startedAt string
	var finishedAt sql.NullString
	var summary string
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&run.ID,
		&run.AccountID,
		&run.Provider,
		&run.Status,
		&startedAt,
		&finishedAt,
		&summary,
		&createdAt,
		&updatedAt,
	); err != nil {
		return model.ScanRun{}, fmt.Errorf("scan run: %w", err)
	}

	var err error
	run.StartedAt, err = parseTime(startedAt)
	if err != nil {
		return model.ScanRun{}, err
	}
	run.FinishedAt, err = parseOptionalTime(finishedAt)
	if err != nil {
		return model.ScanRun{}, err
	}
	run.Summary = json.RawMessage(summary)
	run.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.ScanRun{}, err
	}
	run.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.ScanRun{}, err
	}
	return run, nil
}

func scanScanTaskRun(row rowScanner) (model.ScanTaskRun, error) {
	var task model.ScanTaskRun
	var startedAt string
	var finishedAt string
	var createdAt string

	if err := row.Scan(
		&task.ID,
		&task.ScanRunID,
		&task.AccountID,
		&task.Provider,
		&task.Scope,
		&task.ResourceType,
		&task.Region,
		&task.Status,
		&task.Category,
		&task.Message,
		&task.AssetCount,
		&task.Attempt,
		&startedAt,
		&finishedAt,
		&task.DurationMs,
		&createdAt,
	); err != nil {
		return model.ScanTaskRun{}, fmt.Errorf("scan task run: %w", err)
	}

	var err error
	task.StartedAt, err = parseTime(startedAt)
	if err != nil {
		return model.ScanTaskRun{}, err
	}
	task.FinishedAt, err = parseTime(finishedAt)
	if err != nil {
		return model.ScanTaskRun{}, err
	}
	task.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.ScanTaskRun{}, err
	}
	return task, nil
}

func scanCollectorSkipEntry(row rowScanner) (model.CollectorSkipEntry, error) {
	var entry model.CollectorSkipEntry
	var expiresAt string
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&entry.ID,
		&entry.AccountID,
		&entry.Provider,
		&entry.ResourceType,
		&entry.Region,
		&entry.Category,
		&entry.Message,
		&expiresAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return model.CollectorSkipEntry{}, fmt.Errorf("scan collector skip entry: %w", err)
	}

	var err error
	entry.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return model.CollectorSkipEntry{}, err
	}
	entry.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.CollectorSkipEntry{}, err
	}
	entry.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.CollectorSkipEntry{}, err
	}
	return entry, nil
}

func scanAsset(row rowScanner) (model.Asset, error) {
	var asset model.Asset
	var properties string
	var firstSeenAt string
	var lastSeenAt string
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&asset.ID,
		&asset.AccountID,
		&asset.Provider,
		&asset.ResourceType,
		&asset.ResourceID,
		&asset.Region,
		&asset.Name,
		&properties,
		&firstSeenAt,
		&lastSeenAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return model.Asset{}, fmt.Errorf("scan asset: %w", err)
	}

	var err error
	asset.Properties = json.RawMessage(properties)
	asset.FirstSeenAt, err = parseTime(firstSeenAt)
	if err != nil {
		return model.Asset{}, err
	}
	asset.LastSeenAt, err = parseTime(lastSeenAt)
	if err != nil {
		return model.Asset{}, err
	}
	asset.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.Asset{}, err
	}
	asset.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.Asset{}, err
	}
	return asset, nil
}

func scanAssetViewSummary(row rowScanner) (model.AssetView, error) {
	var view model.AssetView
	var properties string
	var firstSeenAt string
	var lastSeenAt string
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&view.ID,
		&view.AccountID,
		&view.Provider,
		&view.ResourceType,
		&view.ResourceID,
		&view.Region,
		&view.Name,
		&properties,
		&firstSeenAt,
		&lastSeenAt,
		&createdAt,
		&updatedAt,
		&view.FindingCount,
		&view.OpenFindingCount,
		&view.CriticalFindingCount,
		&view.HighFindingCount,
	); err != nil {
		return model.AssetView{}, fmt.Errorf("scan asset view: %w", err)
	}

	var err error
	view.Properties = json.RawMessage(properties)
	view.FirstSeenAt, err = parseTime(firstSeenAt)
	if err != nil {
		return model.AssetView{}, err
	}
	view.LastSeenAt, err = parseTime(lastSeenAt)
	if err != nil {
		return model.AssetView{}, err
	}
	view.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.AssetView{}, err
	}
	view.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.AssetView{}, err
	}
	return view, nil
}

func scanAssetRelationship(row rowScanner) (model.AssetRelationship, error) {
	var relationship model.AssetRelationship
	var properties string
	var firstSeenAt string
	var lastSeenAt string
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&relationship.ID,
		&relationship.AccountID,
		&relationship.Provider,
		&relationship.SourceAssetID,
		&relationship.SourceResourceType,
		&relationship.SourceResourceID,
		&relationship.RelationshipType,
		&relationship.TargetResourceID,
		&properties,
		&firstSeenAt,
		&lastSeenAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return model.AssetRelationship{}, fmt.Errorf("scan asset relationship: %w", err)
	}

	var err error
	relationship.Properties = json.RawMessage(properties)
	relationship.FirstSeenAt, err = parseTime(firstSeenAt)
	if err != nil {
		return model.AssetRelationship{}, err
	}
	relationship.LastSeenAt, err = parseTime(lastSeenAt)
	if err != nil {
		return model.AssetRelationship{}, err
	}
	relationship.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.AssetRelationship{}, err
	}
	relationship.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.AssetRelationship{}, err
	}
	return relationship, nil
}

func scanAssetScanState(row rowScanner) (model.AssetScanState, error) {
	var state model.AssetScanState
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&state.ID,
		&state.ScanRunID,
		&state.AccountID,
		&state.AssetID,
		&state.ResourceType,
		&state.ResourceID,
		&state.Status,
		&createdAt,
		&updatedAt,
	); err != nil {
		return model.AssetScanState{}, fmt.Errorf("scan asset scan state: %w", err)
	}

	var err error
	state.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.AssetScanState{}, err
	}
	state.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.AssetScanState{}, err
	}
	return state, nil
}

func scanFinding(row rowScanner) (model.Finding, error) {
	var finding model.Finding
	var evidence string
	var firstSeenAt string
	var lastSeenAt string
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&finding.ID,
		&finding.ScanRunID,
		&finding.AccountID,
		&finding.AssetID,
		&finding.RuleID,
		&finding.Title,
		&finding.Severity,
		&finding.Status,
		&finding.Message,
		&evidence,
		&finding.Remediation,
		&firstSeenAt,
		&lastSeenAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return model.Finding{}, fmt.Errorf("scan finding: %w", err)
	}

	var err error
	finding.Evidence = json.RawMessage(evidence)
	finding.FirstSeenAt, err = parseTime(firstSeenAt)
	if err != nil {
		return model.Finding{}, err
	}
	finding.LastSeenAt, err = parseTime(lastSeenAt)
	if err != nil {
		return model.Finding{}, err
	}
	finding.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.Finding{}, err
	}
	finding.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.Finding{}, err
	}
	return finding, nil
}

func findingViewSelectSQL() string {
	return `
SELECT f.id, f.scan_run_id, f.account_id, f.asset_id, f.rule_id, f.title, f.severity, f.status, f.message,
    f.evidence_json, f.remediation, f.first_seen_at, f.last_seen_at, f.created_at, f.updated_at,
    a.id, a.account_id, a.provider, a.resource_type, a.resource_id, a.region, a.name
FROM findings f
JOIN assets a ON a.id = f.asset_id
`
}

func scanFindingView(row rowScanner) (model.FindingView, error) {
	var view model.FindingView
	var evidence string
	var firstSeenAt string
	var lastSeenAt string
	var createdAt string
	var updatedAt string

	if err := row.Scan(
		&view.ID,
		&view.ScanRunID,
		&view.AccountID,
		&view.AssetID,
		&view.RuleID,
		&view.Title,
		&view.Severity,
		&view.Status,
		&view.Message,
		&evidence,
		&view.Remediation,
		&firstSeenAt,
		&lastSeenAt,
		&createdAt,
		&updatedAt,
		&view.Asset.ID,
		&view.Asset.AccountID,
		&view.Asset.Provider,
		&view.Asset.ResourceType,
		&view.Asset.ResourceID,
		&view.Asset.Region,
		&view.Asset.Name,
	); err != nil {
		return model.FindingView{}, fmt.Errorf("scan finding view: %w", err)
	}

	var err error
	view.Evidence = json.RawMessage(evidence)
	view.FirstSeenAt, err = parseTime(firstSeenAt)
	if err != nil {
		return model.FindingView{}, err
	}
	view.LastSeenAt, err = parseTime(lastSeenAt)
	if err != nil {
		return model.FindingView{}, err
	}
	view.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return model.FindingView{}, err
	}
	view.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return model.FindingView{}, err
	}
	view.Provider = view.Asset.Provider
	view.Region = view.Asset.Region
	view.AssetResourceType = view.Asset.ResourceType
	view.AssetResourceID = view.Asset.ResourceID
	view.AssetName = view.Asset.Name
	return view, nil
}

func scanRuleView(row rowScanner) (model.RuleView, error) {
	var view model.RuleView
	var severityRank int
	var firstSeenAt string
	var lastSeenAt string

	if err := row.Scan(
		&view.RuleID,
		&view.Title,
		&severityRank,
		&view.Remediation,
		&firstSeenAt,
		&lastSeenAt,
		&view.FindingCount,
		&view.OpenFindingCount,
		&view.AffectedAssetCount,
	); err != nil {
		return model.RuleView{}, fmt.Errorf("scan rule view: %w", err)
	}

	var err error
	view.FirstSeenAt, err = parseTime(firstSeenAt)
	if err != nil {
		return model.RuleView{}, err
	}
	view.LastSeenAt, err = parseTime(lastSeenAt)
	if err != nil {
		return model.RuleView{}, err
	}
	view.ID = view.RuleID
	view.AssetCount = view.AffectedAssetCount
	view.Severity = severityFromRank(severityRank)
	return view, nil
}

func severityFromRank(rank int) string {
	switch rank {
	case 5:
		return model.SeverityCritical
	case 4:
		return model.SeverityHigh
	case 3:
		return model.SeverityMedium
	case 2:
		return model.SeverityLow
	case 1:
		return model.SeverityInfo
	default:
		return model.SeverityUnknown
	}
}

func scanTaskRunInsertSQL() string {
	return `
INSERT INTO scan_task_runs (
    id, scan_run_id, account_id, provider, scope, resource_type, region, status, category, message,
    asset_count, attempt, started_at, finished_at, duration_ms, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, scan_run_id, account_id, provider, scope, resource_type, region, status, category, message,
    asset_count, attempt, started_at, finished_at, duration_ms, created_at
`
}

func scanTaskRunInsertNoReturnSQL() string {
	return `
INSERT INTO scan_task_runs (
    id, scan_run_id, account_id, provider, scope, resource_type, region, status, category, message,
    asset_count, attempt, started_at, finished_at, duration_ms, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`
}

func scanTaskRunArgs(task model.ScanTaskRun) []any {
	return []any{
		task.ID,
		task.ScanRunID,
		task.AccountID,
		task.Provider,
		task.Scope,
		task.ResourceType,
		task.Region,
		task.Status,
		task.Category,
		task.Message,
		task.AssetCount,
		task.Attempt,
		formatTime(task.StartedAt),
		formatTime(task.FinishedAt),
		task.DurationMs,
		formatTime(task.CreatedAt),
	}
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func jsonText(raw json.RawMessage) string {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return "{}"
	}
	return string(raw)
}

func utcNow() time.Time {
	return time.Now().UTC().Round(0)
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func formatOptionalTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	formatted := formatTime(*t)
	return formatted
}

func parseTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return t, nil
	}
	t, err = time.Parse(time.DateTime, value)
	if err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("parse time %q: %w", value, err)
}

func parseOptionalTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid || value.String == "" {
		return nil, nil
	}
	t, err := parseTime(value.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
