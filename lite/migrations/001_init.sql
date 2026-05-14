PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    external_id TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_provider_external_id
    ON accounts(provider, external_id)
    WHERE external_id <> '';

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    properties_json TEXT NOT NULL DEFAULT '{}',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(account_id, resource_type, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_assets_account_type
    ON assets(account_id, resource_type);

CREATE TABLE IF NOT EXISTS asset_relationships (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    source_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source_resource_type TEXT NOT NULL,
    source_resource_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    target_resource_id TEXT NOT NULL,
    properties_json TEXT NOT NULL DEFAULT '{}',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(account_id, source_asset_id, relationship_type, target_resource_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_relationships_account_source
    ON asset_relationships(account_id, source_asset_id);

CREATE INDEX IF NOT EXISTS idx_asset_relationships_account_target
    ON asset_relationships(account_id, target_resource_id);

CREATE INDEX IF NOT EXISTS idx_asset_relationships_type
    ON asset_relationships(relationship_type);

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_account_started
    ON scan_runs(account_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_runs_status
    ON scan_runs(status);

CREATE TABLE IF NOT EXISTS scan_task_runs (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    asset_count INTEGER NOT NULL DEFAULT 0,
    attempt INTEGER NOT NULL DEFAULT 1,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_task_runs_run_duration
    ON scan_task_runs(scan_run_id, duration_ms DESC);

CREATE INDEX IF NOT EXISTS idx_scan_task_runs_account_resource
    ON scan_task_runs(account_id, resource_type, region);

CREATE INDEX IF NOT EXISTS idx_scan_task_runs_status
    ON scan_task_runs(status);

CREATE TABLE IF NOT EXISTS collector_skip_cache (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(account_id, provider, resource_type, region, category)
);

CREATE INDEX IF NOT EXISTS idx_collector_skip_cache_lookup
    ON collector_skip_cache(account_id, provider, resource_type, region, expires_at);

CREATE TABLE IF NOT EXISTS asset_scan_states (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_run_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_scan_states_run_status
    ON asset_scan_states(scan_run_id, status);

CREATE INDEX IF NOT EXISTS idx_asset_scan_states_account_status
    ON asset_scan_states(account_id, status);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    remediation TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_run_id, rule_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_account_status
    ON findings(account_id, status);

CREATE INDEX IF NOT EXISTS idx_findings_scan_run
    ON findings(scan_run_id);

CREATE INDEX IF NOT EXISTS idx_findings_asset
    ON findings(asset_id);

CREATE INDEX IF NOT EXISTS idx_findings_rule
    ON findings(rule_id);

CREATE TABLE IF NOT EXISTS waivers (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_waivers_account_rule
    ON waivers(account_id, rule_id);

CREATE INDEX IF NOT EXISTS idx_waivers_asset_rule
    ON waivers(asset_id, rule_id)
    WHERE asset_id IS NOT NULL;
