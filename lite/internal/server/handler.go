package server

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antgroup/CloudRec/lite/internal/model"
	"github.com/antgroup/CloudRec/lite/internal/rule"
	"github.com/antgroup/CloudRec/lite/internal/storage"
	"github.com/antgroup/CloudRec/lite/providers/alicloud"
)

const (
	defaultFindingsLimit = 100
	maxFindingsLimit     = 1000
	defaultListLimit     = 100
	maxListLimit         = 1000
	defaultGraphDepth    = 1
	maxGraphDepth        = 3
	defaultProvider      = "alicloud"
	defaultRulesDir      = "./rules"
	defaultVersion       = "0.1.0-dev"
)

//go:embed web/*
var embeddedWebFS embed.FS

type Store interface {
	GetSummary(context.Context, storage.SummaryFilter) (model.Summary, error)
	ListAssets(context.Context, storage.AssetFilter) ([]model.Asset, error)
	ListFindings(context.Context, storage.FindingFilter) ([]model.Finding, error)
	ListScanRuns(context.Context, storage.ScanRunFilter) ([]model.ScanRun, error)
	ListAssetRelationships(context.Context, storage.RelationshipFilter) ([]model.AssetRelationship, error)
}

type dashboardGetter interface {
	GetDashboard(context.Context, storage.DashboardFilter) (model.Dashboard, error)
}

type facetsGetter interface {
	GetFacets(context.Context, storage.FacetFilter) (model.FacetSet, error)
}

type graphGetter interface {
	GetGraph(context.Context, storage.GraphFilter) (model.GraphResponse, error)
}

type findingGetter interface {
	GetFinding(context.Context, string) (model.Finding, error)
}

type findingViewGetter interface {
	GetFinding(context.Context, string) (model.FindingView, error)
}

type assetGetter interface {
	GetAsset(context.Context, string) (model.Asset, error)
}

type assetViewGetter interface {
	GetAsset(context.Context, string) (model.AssetView, error)
}

type countAssetsGetter interface {
	CountAssets(context.Context, storage.AssetFilter) (int, error)
}

type countFindingsGetter interface {
	CountFindings(context.Context, storage.FindingFilter) (int, error)
}

type countScanRunsGetter interface {
	CountScanRuns(context.Context, storage.ScanRunFilter) (int, error)
}

type countRelationshipsGetter interface {
	CountAssetRelationships(context.Context, storage.RelationshipFilter) (int, error)
}

type Option func(*handler)

func WithRulesDir(rulesDir string) Option {
	return func(h *handler) {
		h.rulesDir = strings.TrimSpace(rulesDir)
	}
}

func WithProvider(provider string) Option {
	return func(h *handler) {
		h.provider = normalizeProvider(provider)
	}
}

func WithVersion(version string) Option {
	return func(h *handler) {
		h.version = strings.TrimSpace(version)
	}
}

func WithDatabasePath(dbPath string) Option {
	return func(h *handler) {
		h.dbPath = strings.TrimSpace(dbPath)
	}
}

type handler struct {
	store    Store
	rulesDir string
	provider string
	version  string
	dbPath   string
	webFS    fs.FS
	now      func() time.Time
}

func NewHandler(store Store, options ...Option) http.Handler {
	h := &handler{
		store:    store,
		rulesDir: defaultRulesDir,
		provider: defaultProvider,
		version:  defaultVersion,
		webFS:    embeddedWebSubFS(),
		now:      time.Now,
	}
	for _, option := range options {
		option(h)
	}
	if h.rulesDir == "" {
		h.rulesDir = defaultRulesDir
	}
	if h.provider == "" {
		h.provider = defaultProvider
	}
	if h.version == "" {
		h.version = defaultVersion
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.healthz)
	mux.HandleFunc("/api/summary", h.summary)
	mux.HandleFunc("/api/assets", h.assets)
	mux.HandleFunc("/api/findings", h.findings)
	mux.HandleFunc("/api/scan-runs", h.scanRuns)
	mux.HandleFunc("/api/scan-quality", h.scanQuality)
	mux.HandleFunc("/api/relationships", h.relationships)
	mux.HandleFunc("/api/risk-paths", h.riskPaths)
	mux.HandleFunc("/api/dashboard", h.dashboard)
	mux.HandleFunc("/api/facets", h.facets)
	mux.HandleFunc("/api/finding", h.findingDetail)
	mux.HandleFunc("/api/asset", h.assetDetail)
	mux.HandleFunc("/api/graph", h.graph)
	mux.HandleFunc("/api/rules", h.rules)
	mux.HandleFunc("/api/rules/coverage", h.rulesCoverage)
	mux.HandleFunc("/api/runtime", h.runtime)
	mux.HandleFunc("/cloudrec-logo.png", h.logo)
	mux.HandleFunc("/", h.index)
	return mux
}

func embeddedWebSubFS() fs.FS {
	web, err := fs.Sub(embeddedWebFS, "web")
	if err != nil {
		return nil
	}
	return web
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if h.serveStatic(w, r) {
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (h *handler) serveStatic(w http.ResponseWriter, r *http.Request) bool {
	if h.webFS == nil {
		return false
	}

	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "." || name == "" {
		name = "index.html"
	}
	if serveStaticFile(w, r, h.webFS, name) {
		return true
	}
	if !strings.Contains(path.Base(name), ".") {
		return serveStaticFile(w, r, h.webFS, "index.html")
	}
	return false
}

func serveStaticFile(w http.ResponseWriter, r *http.Request, webFS fs.FS, name string) bool {
	info, err := fs.Stat(webFS, name)
	if err != nil || info.IsDir() {
		return false
	}
	http.ServeFileFS(w, r, webFS, name)
	return true
}

func (h *handler) logo(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	for _, candidate := range []string{
		"doc/images/logo.png",
		"../doc/images/logo.png",
		"../../doc/images/logo.png",
	} {
		if _, err := os.Stat(candidate); err == nil {
			w.Header().Set("Cache-Control", "public, max-age=86400")
			http.ServeFile(w, r, candidate)
			return
		}
	}
	http.NotFound(w, r)
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CloudRec Lite</title>
  <style>
    :root {
      --bg: #f5efe3;
      --panel: #fffaf0;
      --ink: #1d2520;
      --muted: #6f766d;
      --line: #d8ccb8;
      --accent: #0e6b5f;
      --accent-2: #c95f37;
      --shadow: 0 24px 60px rgba(64, 48, 24, 0.14);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font: 15px/1.5 Georgia, "Times New Roman", serif;
      background:
        radial-gradient(circle at 20% 10%, rgba(14,107,95,.16), transparent 28rem),
        radial-gradient(circle at 84% 8%, rgba(201,95,55,.18), transparent 24rem),
        linear-gradient(135deg, #f9f2e8, var(--bg));
    }
    main { width: min(1180px, calc(100vw - 32px)); margin: 0 auto; padding: 36px 0 48px; }
    header { display: flex; justify-content: space-between; gap: 24px; align-items: flex-end; margin-bottom: 28px; }
    h1 { margin: 0; font-size: clamp(34px, 6vw, 72px); line-height: .9; letter-spacing: -0.06em; }
    h2 { margin: 0 0 14px; font-size: 18px; letter-spacing: .02em; }
    .eyebrow { margin: 0 0 8px; color: var(--accent-2); font: 700 12px/1.1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; letter-spacing: .16em; }
    .toolbar, .card { background: rgba(255,250,240,.86); border: 1px solid var(--line); border-radius: 24px; box-shadow: var(--shadow); }
    .toolbar { padding: 16px; display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-bottom: 18px; backdrop-filter: blur(14px); }
    label { display: grid; gap: 6px; color: var(--muted); font: 700 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; letter-spacing: .08em; }
    input, select, button { width: 100%; border: 1px solid var(--line); border-radius: 14px; padding: 11px 12px; color: var(--ink); background: #fffdf8; font: 14px/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; }
    button { cursor: pointer; border-color: var(--accent); background: var(--accent); color: white; font-weight: 800; }
    .grid { display: grid; grid-template-columns: 1.1fr .9fr; gap: 18px; }
    .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px; }
    .card { padding: 18px; overflow: hidden; }
    .metric { font-size: 34px; line-height: 1; letter-spacing: -0.04em; }
    .muted { color: var(--muted); }
    .tabs { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
    .tab { width: auto; padding: 9px 13px; background: transparent; color: var(--accent); }
    .tab.active { background: var(--accent); color: white; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px 8px; border-bottom: 1px solid rgba(216,204,184,.75); text-align: left; vertical-align: top; }
    th { color: var(--muted); font: 700 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; letter-spacing: .08em; }
    td { font-size: 14px; }
    code, .pill { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .pill { display: inline-flex; border: 1px solid var(--line); border-radius: 999px; padding: 2px 8px; font-size: 12px; background: #fffdf8; }
    .status { min-height: 22px; margin: 8px 0 0; color: var(--muted); font: 13px/1.3 ui-monospace, SFMono-Regular, Menlo, monospace; }
    @media (max-width: 860px) {
      header, .grid { display: block; }
      .toolbar, .cards { grid-template-columns: 1fr 1fr; }
      .card { margin-bottom: 14px; }
    }
    @media (max-width: 560px) {
      .toolbar, .cards { grid-template-columns: 1fr; }
      main { width: min(100vw - 20px, 1180px); padding-top: 20px; }
      th:nth-child(4), td:nth-child(4) { display: none; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <p class="eyebrow">Local CSPM dashboard</p>
        <h1>CloudRec Lite</h1>
      </div>
      <p class="muted">Summary, findings, assets, scan runs, and relationships from the local SQLite store.</p>
    </header>
    <section class="toolbar">
      <label>Account ID <input id="account" placeholder="all accounts"></label>
      <label>Resource Type <input id="resourceType" placeholder="storage.bucket"></label>
      <label>Severity <select id="severity"><option value="">all</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option><option>unknown</option></select></label>
      <label>Status <select id="status"><option value="">all</option><option>open</option><option>resolved</option><option>suppressed</option></select></label>
      <label>Limit <input id="limit" type="number" min="1" max="1000" value="100"></label>
      <button id="refresh">Refresh</button>
    </section>
    <section class="cards" id="summaryCards"></section>
    <section class="grid">
      <div class="card">
        <h2>Explorer</h2>
        <div class="tabs">
          <button class="tab active" data-tab="findings">Findings</button>
          <button class="tab" data-tab="assets">Assets</button>
          <button class="tab" data-tab="relationships">Relationships</button>
          <button class="tab" data-tab="scan-runs">Scan Runs</button>
        </div>
        <div id="table"></div>
      </div>
      <aside class="card">
        <h2>Latest Scan Delta</h2>
        <div id="delta"></div>
        <p class="status" id="statusLine"></p>
      </aside>
    </section>
  </main>
  <script>
    const state = { tab: "findings" };
    const $ = (id) => document.getElementById(id);
    const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[ch]));
    const params = (extra = {}) => {
      const q = new URLSearchParams();
      const account = $("account").value.trim();
      const resourceType = $("resourceType").value.trim();
      const limit = $("limit").value.trim() || "100";
      if (account) q.set("account_id", account);
      if (resourceType) q.set("resource_type", resourceType);
      q.set("limit", limit);
      for (const [key, value] of Object.entries(extra)) if (value) q.set(key, value);
      return q.toString();
    };
    async function getJSON(path) {
      const res = await fetch(path);
      if (!res.ok) throw new Error((await res.json()).error || res.statusText);
      return res.json();
    }
    function renderSummary(summary) {
      const cards = [
        ["Assets", summary.asset_count],
        ["Open Findings", summary.open_finding_count],
        ["Relationships", summary.relationship_count],
        ["All Findings", summary.finding_count],
      ];
      $("summaryCards").innerHTML = cards.map(([label, value]) => '<article class="card"><div class="metric">' + esc(value) + '</div><div class="muted">' + esc(label) + '</div></article>').join("");
      const delta = summary.scan_delta || {};
      $("delta").innerHTML = '<p><span class="pill">added ' + esc(delta.added_assets || 0) + '</span> <span class="pill">updated ' + esc(delta.updated_assets || 0) + '</span> <span class="pill">missing ' + esc(delta.missing_assets || 0) + '</span> <span class="pill">seen ' + esc(delta.seen_assets || 0) + '</span></p><p class="muted">Latest scan: ' + esc(summary.latest_scan_run?.id || "none") + '</p>';
    }
    function table(headers, rows) {
      return '<table><thead><tr>' + headers.map((h) => '<th>' + esc(h) + '</th>').join("") + '</tr></thead><tbody>' + (rows.join("") || '<tr><td colspan="' + headers.length + '" class="muted">No data yet.</td></tr>') + '</tbody></table>';
    }
    async function renderTab() {
      const limit = $("limit").value.trim() || "100";
      if (state.tab === "findings") {
        const severity = $("severity").value;
        const status = $("status").value;
        const data = await getJSON('/api/findings?' + params({ severity, status }));
        $("table").innerHTML = table(["Severity", "Status", "Rule", "Title"], data.findings.map((f) => '<tr><td><span class="pill">' + esc(f.severity) + '</span></td><td>' + esc(f.status) + '</td><td><code>' + esc(f.rule_id) + '</code></td><td>' + esc(f.title) + '</td></tr>'));
      } else if (state.tab === "assets") {
        const data = await getJSON('/api/assets?' + params());
        $("table").innerHTML = table(["Type", "Name", "Region", "Resource ID"], data.assets.map((a) => '<tr><td>' + esc(a.resource_type) + '</td><td>' + esc(a.name) + '</td><td>' + esc(a.region) + '</td><td><code>' + esc(a.resource_id) + '</code></td></tr>'));
      } else if (state.tab === "relationships") {
        const data = await getJSON('/api/relationships?' + params());
        $("table").innerHTML = table(["Type", "Source", "Target", "Updated"], data.relationships.map((r) => '<tr><td>' + esc(r.relationship_type) + '</td><td><code>' + esc(r.source_resource_id) + '</code></td><td><code>' + esc(r.target_resource_id) + '</code></td><td>' + esc(r.updated_at) + '</td></tr>'));
      } else {
        const q = new URLSearchParams();
        const account = $("account").value.trim();
        if (account) q.set("account_id", account);
        q.set("limit", limit);
        const data = await getJSON('/api/scan-runs?' + q.toString());
        $("table").innerHTML = table(["Started", "Status", "Assets", "Findings"], data.scan_runs.map((r) => {
          const s = r.summary || {};
          return '<tr><td>' + esc(r.started_at) + '</td><td><span class="pill">' + esc(r.status) + '</span></td><td>' + esc(s.assets ?? "") + '</td><td>' + esc(s.findings ?? "") + '</td></tr>';
        }));
      }
    }
    async function refresh() {
      $("statusLine").textContent = "Loading...";
      try {
        const summaryQ = new URLSearchParams();
        const account = $("account").value.trim();
        if (account) summaryQ.set("account_id", account);
        renderSummary(await getJSON('/api/summary?' + summaryQ.toString()));
        await renderTab();
        $("statusLine").textContent = "Updated " + new Date().toLocaleTimeString();
      } catch (err) {
        $("statusLine").textContent = err.message;
      }
    }
    document.querySelectorAll(".tab").forEach((button) => button.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      button.classList.add("active");
      state.tab = button.dataset.tab;
      refresh();
    }));
    $("refresh").addEventListener("click", refresh);
    ["account", "resourceType", "severity", "status", "limit"].forEach((id) => $(id).addEventListener("change", refresh));
    refresh();
  </script>
</body>
</html>`

func (h *handler) healthz(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handler) summary(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	summary, err := h.store.GetSummary(r.Context(), storage.SummaryFilter{
		AccountID: strings.TrimSpace(r.URL.Query().Get("account_id")),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get summary failed")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (h *handler) assets(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, err := parseAssetFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	assets, err := h.store.ListAssets(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list assets failed")
		return
	}
	if assets == nil {
		assets = []model.Asset{}
	}
	total := len(assets)
	if counter, ok := h.store.(countAssetsGetter); ok {
		if count, err := counter.CountAssets(r.Context(), filter); err == nil {
			total = count
		}
	}
	writeJSON(w, http.StatusOK, assetsResponse{Assets: assets, Count: len(assets), Total: total, Limit: filter.Limit, Offset: filter.Offset})
}

func (h *handler) findings(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, err := parseFindingFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	findings, err := h.store.ListFindings(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list findings failed")
		return
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	findings = h.enrichFindingsWithRuleRemediation(findings)
	total := len(findings)
	if counter, ok := h.store.(countFindingsGetter); ok {
		if count, err := counter.CountFindings(r.Context(), filter); err == nil {
			total = count
		}
	}

	writeJSON(w, http.StatusOK, findingsResponse{
		Findings: findings,
		Count:    len(findings),
		Total:    total,
		Limit:    filter.Limit,
		Offset:   filter.Offset,
	})
}

func (h *handler) scanRuns(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, err := parseScanRunFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	runs, err := h.store.ListScanRuns(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list scan runs failed")
		return
	}
	if runs == nil {
		runs = []model.ScanRun{}
	}
	total := len(runs)
	if counter, ok := h.store.(countScanRunsGetter); ok {
		if count, err := counter.CountScanRuns(r.Context(), filter); err == nil {
			total = count
		}
	}
	writeJSON(w, http.StatusOK, scanRunsResponse{ScanRuns: runs, Count: len(runs), Total: total, Limit: filter.Limit, Offset: filter.Offset})
}

func (h *handler) relationships(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, err := parseRelationshipFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	relationships, err := h.store.ListAssetRelationships(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list relationships failed")
		return
	}
	if relationships == nil {
		relationships = []model.AssetRelationship{}
	}
	total := len(relationships)
	if counter, ok := h.store.(countRelationshipsGetter); ok {
		if count, err := counter.CountAssetRelationships(r.Context(), filter); err == nil {
			total = count
		}
	}
	writeJSON(w, http.StatusOK, relationshipsResponse{Relationships: relationships, Count: len(relationships), Total: total, Limit: filter.Limit, Offset: filter.Offset})
}

func (h *handler) dashboard(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, err := parseDashboardFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if getter, ok := h.store.(dashboardGetter); ok {
		dashboard, err := getter.GetDashboard(r.Context(), storage.DashboardFilter{
			AccountID: filter.AccountID,
			Provider:  filter.Provider,
			Region:    filter.Region,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "get dashboard failed")
			return
		}
		writeJSON(w, http.StatusOK, dashboard)
		return
	}
	summary, err := h.store.GetSummary(r.Context(), storage.SummaryFilter{
		AccountID: filter.AccountID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get summary failed")
		return
	}
	findings, err := h.store.ListFindings(r.Context(), storage.FindingFilter{
		AccountID:    filter.AccountID,
		ResourceType: filter.ResourceType,
		RuleID:       filter.RuleID,
		Severity:     filter.Severity,
		Status:       filter.Status,
		Limit:        filter.Limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list dashboard findings failed")
		return
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	runs, err := h.store.ListScanRuns(r.Context(), storage.ScanRunFilter{
		AccountID: filter.AccountID,
		Provider:  filter.Provider,
		Status:    filter.ScanStatus,
		Limit:     filter.Limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list dashboard scan runs failed")
		return
	}
	if runs == nil {
		runs = []model.ScanRun{}
	}

	writeJSON(w, http.StatusOK, dashboardResponse{
		Summary:        summary,
		TopFindings:    findings,
		RecentScanRuns: runs,
		GeneratedAt:    h.now().UTC(),
	})
}

func (h *handler) facets(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, err := parseFacetFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if getter, ok := h.store.(facetsGetter); ok {
		facets, err := getter.GetFacets(r.Context(), storage.FacetFilter{
			AccountID:    filter.AccountID,
			Provider:     filter.Provider,
			ResourceType: filter.ResourceType,
			Region:       filter.Region,
			Status:       filter.Status,
			Severity:     filter.Severity,
			Q:            filter.Q,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "get facets failed")
			return
		}
		writeJSON(w, http.StatusOK, facets)
		return
	}
	assets, err := h.store.ListAssets(r.Context(), storage.AssetFilter{
		AccountID:    filter.AccountID,
		Provider:     filter.Provider,
		ResourceType: filter.ResourceType,
		Region:       filter.Region,
		Q:            filter.Q,
		Limit:        filter.Limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list facet assets failed")
		return
	}
	findings, err := h.store.ListFindings(r.Context(), storage.FindingFilter{
		AccountID:    filter.AccountID,
		ResourceType: filter.ResourceType,
		RuleID:       filter.RuleID,
		Severity:     filter.Severity,
		Status:       filter.Status,
		Region:       filter.Region,
		Q:            filter.Q,
		Limit:        filter.Limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list facet findings failed")
		return
	}
	runs, err := h.store.ListScanRuns(r.Context(), storage.ScanRunFilter{
		AccountID: filter.AccountID,
		Provider:  filter.Provider,
		Status:    filter.ScanStatus,
		Limit:     filter.Limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list facet scan runs failed")
		return
	}

	writeJSON(w, http.StatusOK, buildFacetsResponse(assets, findings, runs))
}

func (h *handler) findingDetail(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	id := firstQueryValue(r, "id", "finding_id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	if getter, ok := h.store.(findingViewGetter); ok {
		view, err := getter.GetFinding(r.Context(), id)
		if err != nil {
			if isNotFoundError(err) {
				writeError(w, http.StatusNotFound, "finding not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "get finding failed")
			return
		}
		view = h.enrichFindingViewWithRuleRemediation(view)
		writeJSON(w, http.StatusOK, map[string]any{"finding": view, "asset": view.Asset})
		return
	}
	finding, ok, err := h.lookupFinding(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get finding failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	finding = h.enrichFindingWithRuleRemediation(finding)
	writeJSON(w, http.StatusOK, findingDetailResponse{Finding: finding})
}

func (h *handler) assetDetail(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, err := parseAssetDetailFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if filter.ID != "" {
		if getter, ok := h.store.(assetViewGetter); ok {
			view, err := getter.GetAsset(r.Context(), filter.ID)
			if err != nil {
				if isNotFoundError(err) {
					writeError(w, http.StatusNotFound, "asset not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "get asset failed")
				return
			}
			view = h.enrichAssetViewWithRuleRemediation(view)
			view.ProductSummary = productSummaryForAsset(view.Asset)
			writeJSON(w, http.StatusOK, map[string]any{
				"asset":         view,
				"findings":      view.Findings,
				"relationships": view.Relationships,
			})
			return
		}
	}
	asset, ok, err := h.lookupAsset(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get asset failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}

	findings, err := h.store.ListFindings(r.Context(), storage.FindingFilter{
		AccountID: filter.AccountID,
		AssetID:   asset.ID,
		Limit:     filter.Limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list asset findings failed")
		return
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	findings = h.enrichFindingsWithRuleRemediation(findings)

	relationships, err := h.assetRelationships(r.Context(), asset, filter.Limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list asset relationships failed")
		return
	}
	writeJSON(w, http.StatusOK, assetDetailResponse{
		Asset:          asset,
		ProductSummary: productSummaryForAsset(asset),
		Findings:       findings,
		Relationships:  relationships,
	})
}

func (h *handler) graph(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "store is not configured")
		return
	}

	filter, depth, err := parseGraphFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if getter, ok := h.store.(graphGetter); ok {
		graph, err := getter.GetGraph(r.Context(), storage.GraphFilter{
			AccountID:    filter.AccountID,
			Provider:     filter.Provider,
			AssetID:      filter.SourceAssetID,
			ResourceType: filter.ResourceType,
			ResourceID:   firstNonEmptyString(filter.SourceResourceID, filter.TargetResourceID),
			Region:       filter.Region,
			Depth:        depth,
			Limit:        filter.Limit,
			Offset:       filter.Offset,
			Q:            filter.Q,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "get graph failed")
			return
		}
		writeJSON(w, http.StatusOK, graph)
		return
	}
	relationships, err := h.store.ListAssetRelationships(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list graph relationships failed")
		return
	}
	if relationships == nil {
		relationships = []model.AssetRelationship{}
	}
	writeJSON(w, http.StatusOK, buildGraphResponse(relationships, depth))
}

func (h *handler) rules(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if err := ValidateRulesDir(h.rulesDir); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	filter, err := parseRulesFilter(r, h.provider)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	packs, err := rule.LoadDirWithOptions(h.rulesDir, rule.LoadDirOptions{IncludeDisabled: true})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load rules failed: "+err.Error())
		return
	}
	rules := make([]ruleListItem, 0, len(packs))
	for _, pack := range packs {
		item := ruleListItemFromPack(pack, h.provider)
		if !ruleMatchesFilter(item, filter) {
			continue
		}
		rules = append(rules, item)
	}
	sortRuleList(rules, filter.Sort)
	total := len(rules)
	rules = paginateRuleList(rules, filter.Offset, filter.Limit)
	writeJSON(w, http.StatusOK, rulesResponse{
		Rules:    rules,
		Count:    len(rules),
		Total:    total,
		Limit:    filter.Limit,
		Offset:   filter.Offset,
		RulesDir: h.rulesDir,
		Provider: filter.Provider,
	})
}

func (h *handler) rulesCoverage(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	if err := ValidateRulesDir(h.rulesDir); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	provider := normalizeProvider(firstNonEmptyString(r.URL.Query().Get("provider"), h.provider))
	options := coverageOptions(h.rulesDir, provider)
	options.SamplesDir = strings.TrimSpace(r.URL.Query().Get("samples"))
	if options.SamplesDir == "" {
		options.SamplesDir = defaultSamplesDir(h.rulesDir, provider)
	}
	options.ReviewLedgerPath = strings.TrimSpace(r.URL.Query().Get("review_ledger"))
	if options.ReviewLedgerPath == "" {
		options.ReviewLedgerPath = defaultReviewLedgerPath(h.rulesDir)
	}
	report, err := rule.AnalyzeCoverage(options)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analyze rules coverage failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *handler) runtime(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}

	rulesAvailable := true
	rulesError := ""
	if err := ValidateRulesDir(h.rulesDir); err != nil {
		rulesAvailable = false
		rulesError = err.Error()
	}
	writeJSON(w, http.StatusOK, runtimeResponse{
		Version:         h.version,
		Provider:        h.provider,
		RulesDir:        h.rulesDir,
		DatabasePath:    h.dbPath,
		StoreConfigured: h.store != nil,
		RulesAvailable:  rulesAvailable,
		RulesError:      rulesError,
		Endpoints: []string{
			"/api/dashboard",
			"/api/facets",
			"/api/finding",
			"/api/asset",
			"/api/graph",
			"/api/rules",
			"/api/rules/coverage",
			"/api/runtime",
			"/api/summary",
			"/api/assets",
			"/api/findings",
			"/api/scan-runs",
			"/api/scan-quality",
			"/api/relationships",
			"/api/risk-paths",
		},
	})
}

func parseFindingFilter(r *http.Request) (storage.FindingFilter, error) {
	q := r.URL.Query()

	limit, err := parseLimit(q.Get("limit"), defaultFindingsLimit, maxFindingsLimit)
	if err != nil {
		return storage.FindingFilter{}, err
	}
	offset, err := parseOffset(q.Get("offset"))
	if err != nil {
		return storage.FindingFilter{}, err
	}

	return storage.FindingFilter{
		AccountID:    strings.TrimSpace(q.Get("account_id")),
		Provider:     strings.TrimSpace(q.Get("provider")),
		ScanRunID:    strings.TrimSpace(q.Get("scan_run_id")),
		AssetID:      strings.TrimSpace(q.Get("asset_id")),
		ResourceType: strings.TrimSpace(q.Get("resource_type")),
		Region:       strings.TrimSpace(q.Get("region")),
		RuleID:       strings.TrimSpace(q.Get("rule_id")),
		Severity:     strings.TrimSpace(q.Get("severity")),
		Status:       strings.TrimSpace(q.Get("status")),
		Q:            strings.TrimSpace(q.Get("q")),
		Sort:         strings.TrimSpace(q.Get("sort")),
		Limit:        limit,
		Offset:       offset,
	}, nil
}

func parseAssetFilter(r *http.Request) (storage.AssetFilter, error) {
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"), defaultListLimit, maxListLimit)
	if err != nil {
		return storage.AssetFilter{}, err
	}
	offset, err := parseOffset(q.Get("offset"))
	if err != nil {
		return storage.AssetFilter{}, err
	}
	return storage.AssetFilter{
		AccountID:    strings.TrimSpace(q.Get("account_id")),
		Provider:     strings.TrimSpace(q.Get("provider")),
		ResourceType: strings.TrimSpace(q.Get("resource_type")),
		ResourceID:   strings.TrimSpace(q.Get("resource_id")),
		Region:       strings.TrimSpace(q.Get("region")),
		Q:            strings.TrimSpace(q.Get("q")),
		Sort:         strings.TrimSpace(q.Get("sort")),
		Limit:        limit,
		Offset:       offset,
	}, nil
}

func parseScanRunFilter(r *http.Request) (storage.ScanRunFilter, error) {
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"), defaultListLimit, maxListLimit)
	if err != nil {
		return storage.ScanRunFilter{}, err
	}
	offset, err := parseOffset(q.Get("offset"))
	if err != nil {
		return storage.ScanRunFilter{}, err
	}
	return storage.ScanRunFilter{
		AccountID: strings.TrimSpace(q.Get("account_id")),
		Provider:  strings.TrimSpace(q.Get("provider")),
		Status:    strings.TrimSpace(q.Get("status")),
		Q:         strings.TrimSpace(q.Get("q")),
		Sort:      strings.TrimSpace(q.Get("sort")),
		Limit:     limit,
		Offset:    offset,
	}, nil
}

func parseRelationshipFilter(r *http.Request) (storage.RelationshipFilter, error) {
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"), defaultListLimit, maxListLimit)
	if err != nil {
		return storage.RelationshipFilter{}, err
	}
	offset, err := parseOffset(q.Get("offset"))
	if err != nil {
		return storage.RelationshipFilter{}, err
	}
	return storage.RelationshipFilter{
		AccountID:        strings.TrimSpace(q.Get("account_id")),
		SourceAssetID:    strings.TrimSpace(q.Get("source_asset_id")),
		SourceResourceID: strings.TrimSpace(q.Get("source_resource_id")),
		TargetResourceID: strings.TrimSpace(q.Get("target_resource_id")),
		ResourceType:     strings.TrimSpace(q.Get("resource_type")),
		RelationshipType: strings.TrimSpace(q.Get("relationship_type")),
		Region:           strings.TrimSpace(q.Get("region")),
		Q:                strings.TrimSpace(q.Get("q")),
		Sort:             strings.TrimSpace(q.Get("sort")),
		Limit:            limit,
		Offset:           offset,
	}, nil
}

type dashboardFilter struct {
	AccountID    string
	Provider     string
	ResourceType string
	RuleID       string
	Severity     string
	Status       string
	ScanStatus   string
	Region       string
	Q            string
	Limit        int
}

func parseDashboardFilter(r *http.Request) (dashboardFilter, error) {
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"), 10, maxListLimit)
	if err != nil {
		return dashboardFilter{}, err
	}
	return dashboardFilter{
		AccountID:    strings.TrimSpace(q.Get("account_id")),
		Provider:     normalizeProvider(q.Get("provider")),
		ResourceType: strings.TrimSpace(q.Get("resource_type")),
		RuleID:       strings.TrimSpace(q.Get("rule_id")),
		Severity:     strings.TrimSpace(q.Get("severity")),
		Status:       strings.TrimSpace(q.Get("status")),
		ScanStatus:   strings.TrimSpace(q.Get("scan_status")),
		Region:       strings.TrimSpace(q.Get("region")),
		Q:            strings.TrimSpace(q.Get("q")),
		Limit:        limit,
	}, nil
}

type facetFilter struct {
	AccountID    string
	Provider     string
	ResourceType string
	RuleID       string
	Severity     string
	Status       string
	ScanStatus   string
	Region       string
	Q            string
	Limit        int
}

func parseFacetFilter(r *http.Request) (facetFilter, error) {
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"), maxListLimit, maxListLimit)
	if err != nil {
		return facetFilter{}, err
	}
	return facetFilter{
		AccountID:    strings.TrimSpace(q.Get("account_id")),
		Provider:     normalizeProvider(q.Get("provider")),
		ResourceType: strings.TrimSpace(q.Get("resource_type")),
		RuleID:       strings.TrimSpace(q.Get("rule_id")),
		Severity:     strings.TrimSpace(q.Get("severity")),
		Status:       strings.TrimSpace(q.Get("status")),
		ScanStatus:   strings.TrimSpace(q.Get("scan_status")),
		Region:       strings.TrimSpace(q.Get("region")),
		Q:            strings.TrimSpace(q.Get("q")),
		Limit:        limit,
	}, nil
}

type assetDetailFilter struct {
	ID           string
	AccountID    string
	Provider     string
	ResourceType string
	ResourceID   string
	Limit        int
}

func parseAssetDetailFilter(r *http.Request) (assetDetailFilter, error) {
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"), defaultListLimit, maxListLimit)
	if err != nil {
		return assetDetailFilter{}, err
	}
	filter := assetDetailFilter{
		ID:           firstQueryValue(r, "id", "asset_id"),
		AccountID:    strings.TrimSpace(q.Get("account_id")),
		Provider:     normalizeProvider(q.Get("provider")),
		ResourceType: strings.TrimSpace(q.Get("resource_type")),
		ResourceID:   strings.TrimSpace(q.Get("resource_id")),
		Limit:        limit,
	}
	if filter.ID == "" && filter.ResourceID == "" {
		return assetDetailFilter{}, errors.New("id or resource_id is required")
	}
	return filter, nil
}

func parseGraphFilter(r *http.Request) (storage.RelationshipFilter, int, error) {
	filter, err := parseRelationshipFilter(r)
	if err != nil {
		return storage.RelationshipFilter{}, 0, err
	}
	q := r.URL.Query()
	if filter.SourceAssetID == "" {
		filter.SourceAssetID = firstQueryValue(r, "asset_id")
	}
	if filter.SourceResourceID == "" {
		filter.SourceResourceID = strings.TrimSpace(q.Get("resource_id"))
	}
	depth, err := parseDepth(q.Get("depth"))
	if err != nil {
		return storage.RelationshipFilter{}, 0, err
	}
	return filter, depth, nil
}

type rulesFilter struct {
	Provider     string
	ResourceType string
	Severity     string
	RuleID       string
	Enabled      *bool
	Q            string
	Sort         string
	Limit        int
	Offset       int
}

func parseRulesFilter(r *http.Request, defaultProvider string) (rulesFilter, error) {
	q := r.URL.Query()
	limit, err := parseLimit(q.Get("limit"), maxListLimit, maxListLimit)
	if err != nil {
		return rulesFilter{}, err
	}
	offset, err := parseOffset(q.Get("offset"))
	if err != nil {
		return rulesFilter{}, err
	}
	enabled, err := parseOptionalBool(firstNonEmptyString(q.Get("enabled"), q.Get("disabled")))
	if err != nil {
		return rulesFilter{}, err
	}
	if strings.TrimSpace(q.Get("disabled")) != "" && enabled != nil {
		inverted := !*enabled
		enabled = &inverted
	}
	return rulesFilter{
		Provider:     normalizeProvider(firstNonEmptyString(q.Get("provider"), defaultProvider)),
		ResourceType: strings.TrimSpace(q.Get("resource_type")),
		Severity:     strings.TrimSpace(q.Get("severity")),
		RuleID:       strings.TrimSpace(q.Get("rule_id")),
		Enabled:      enabled,
		Q:            strings.TrimSpace(q.Get("q")),
		Sort:         strings.TrimSpace(q.Get("sort")),
		Limit:        limit,
		Offset:       offset,
	}, nil
}

func parseLimit(raw string, defaultLimit int, maxLimit int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultLimit, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 0, errors.New("limit must be a positive integer")
	}
	if parsed > maxLimit {
		return 0, errors.New("limit must be less than or equal to 1000")
	}
	return parsed, nil
}

func parseOffset(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 0 {
		return 0, errors.New("offset must be a non-negative integer")
	}
	return parsed, nil
}

func parseDepth(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultGraphDepth, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 0, errors.New("depth must be a positive integer")
	}
	if parsed > maxGraphDepth {
		return 0, fmt.Errorf("depth must be less than or equal to %d", maxGraphDepth)
	}
	return parsed, nil
}

func parseOptionalBool(raw string) (*bool, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return nil, nil
	}
	switch raw {
	case "1", "t", "true", "y", "yes":
		value := true
		return &value, nil
	case "0", "f", "false", "n", "no":
		value := false
		return &value, nil
	default:
		return nil, fmt.Errorf("boolean value %q is invalid", raw)
	}
}

func (h *handler) lookupFinding(ctx context.Context, id string) (model.Finding, bool, error) {
	if getter, ok := h.store.(findingGetter); ok {
		finding, err := getter.GetFinding(ctx, id)
		if err != nil {
			if isNotFoundError(err) {
				return model.Finding{}, false, nil
			}
			return model.Finding{}, false, err
		}
		if strings.TrimSpace(finding.ID) == "" {
			return model.Finding{}, false, nil
		}
		return finding, true, nil
	}

	findings, err := h.store.ListFindings(ctx, storage.FindingFilter{Limit: maxListLimit})
	if err != nil {
		return model.Finding{}, false, err
	}
	for _, finding := range findings {
		if finding.ID == id {
			return finding, true, nil
		}
	}
	return model.Finding{}, false, nil
}

func (h *handler) lookupAsset(ctx context.Context, filter assetDetailFilter) (model.Asset, bool, error) {
	if filter.ID != "" {
		if getter, ok := h.store.(assetGetter); ok {
			asset, err := getter.GetAsset(ctx, filter.ID)
			if err != nil {
				if isNotFoundError(err) {
					return model.Asset{}, false, nil
				}
				return model.Asset{}, false, err
			}
			if strings.TrimSpace(asset.ID) == "" {
				return model.Asset{}, false, nil
			}
			return asset, true, nil
		}
	}

	assets, err := h.store.ListAssets(ctx, storage.AssetFilter{
		AccountID:    filter.AccountID,
		Provider:     filter.Provider,
		ResourceType: filter.ResourceType,
		ResourceID:   filter.ResourceID,
		Limit:        filter.Limit,
	})
	if err != nil {
		return model.Asset{}, false, err
	}
	for _, asset := range assets {
		if filter.ID != "" && asset.ID != filter.ID {
			continue
		}
		return asset, true, nil
	}
	return model.Asset{}, false, nil
}

func (h *handler) assetRelationships(ctx context.Context, asset model.Asset, limit int) ([]model.AssetRelationship, error) {
	outgoing, err := h.store.ListAssetRelationships(ctx, storage.RelationshipFilter{
		AccountID:     asset.AccountID,
		SourceAssetID: asset.ID,
		Limit:         limit,
	})
	if err != nil {
		return nil, err
	}
	incoming, err := h.store.ListAssetRelationships(ctx, storage.RelationshipFilter{
		AccountID:        asset.AccountID,
		TargetResourceID: asset.ResourceID,
		Limit:            limit,
	})
	if err != nil {
		return nil, err
	}
	relationships := append([]model.AssetRelationship{}, outgoing...)
	seen := map[string]bool{}
	for _, relationship := range relationships {
		seen[relationship.ID] = true
	}
	for _, relationship := range incoming {
		if seen[relationship.ID] {
			continue
		}
		relationships = append(relationships, relationship)
	}
	if relationships == nil {
		relationships = []model.AssetRelationship{}
	}
	return relationships, nil
}

func buildFacetsResponse(assets []model.Asset, findings []model.Finding, runs []model.ScanRun) facetsResponse {
	providers := map[string]int{}
	accounts := map[string]int{}
	resourceTypes := map[string]int{}
	regions := map[string]int{}
	severities := map[string]int{}
	statuses := map[string]int{}
	rules := map[string]int{}
	scanStatuses := map[string]int{}

	for _, asset := range assets {
		incrementFacet(providers, asset.Provider)
		incrementFacet(accounts, asset.AccountID)
		incrementFacet(resourceTypes, asset.ResourceType)
		incrementFacet(regions, asset.Region)
	}
	for _, finding := range findings {
		incrementFacet(accounts, finding.AccountID)
		incrementFacet(severities, finding.Severity)
		incrementFacet(statuses, finding.Status)
		incrementFacet(rules, finding.RuleID)
	}
	for _, run := range runs {
		incrementFacet(providers, run.Provider)
		incrementFacet(accounts, run.AccountID)
		incrementFacet(scanStatuses, run.Status)
	}

	return facetsResponse{
		Providers:     sortedFacets(providers),
		Accounts:      sortedFacets(accounts),
		ResourceTypes: sortedFacets(resourceTypes),
		Regions:       sortedFacets(regions),
		Severities:    sortedFacets(severities),
		Statuses:      sortedFacets(statuses),
		Rules:         sortedFacets(rules),
		ScanStatuses:  sortedFacets(scanStatuses),
	}
}

func incrementFacet(values map[string]int, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	values[value]++
}

func sortedFacets(values map[string]int) []facetValue {
	facets := make([]facetValue, 0, len(values))
	for value, count := range values {
		facets = append(facets, facetValue{Value: value, Count: count})
	}
	sort.Slice(facets, func(i, j int) bool {
		if facets[i].Count != facets[j].Count {
			return facets[i].Count > facets[j].Count
		}
		return facets[i].Value < facets[j].Value
	})
	if facets == nil {
		return []facetValue{}
	}
	return facets
}

func buildGraphResponse(relationships []model.AssetRelationship, depth int) graphResponse {
	nodesByID := map[string]graphNode{}
	edges := make([]graphEdge, 0, len(relationships))
	for _, relationship := range relationships {
		sourceID := firstNonEmptyString(relationship.SourceResourceID, relationship.SourceAssetID)
		targetID := relationship.TargetResourceID
		if sourceID != "" {
			nodesByID[sourceID] = graphNode{
				ID:           sourceID,
				ResourceID:   relationship.SourceResourceID,
				ResourceType: relationship.SourceResourceType,
				AccountID:    relationship.AccountID,
				Provider:     relationship.Provider,
			}
		}
		if targetID != "" {
			node := nodesByID[targetID]
			node.ID = targetID
			node.ResourceID = targetID
			node.AccountID = relationship.AccountID
			node.Provider = relationship.Provider
			nodesByID[targetID] = node
		}
		edges = append(edges, graphEdge{
			ID:               relationship.ID,
			Source:           sourceID,
			Target:           targetID,
			RelationshipType: relationship.RelationshipType,
			Properties:       relationship.Properties,
		})
	}
	nodes := make([]graphNode, 0, len(nodesByID))
	for _, node := range nodesByID {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	return graphResponse{
		Nodes:         nodes,
		Edges:         edges,
		Relationships: relationships,
		Depth:         depth,
		Count:         len(relationships),
	}
}

func ruleListItemFromPack(pack rule.RulePack, defaultProvider string) ruleListItem {
	metadata := pack.Metadata
	provider := normalizeProvider(firstNonEmptyString(metadata.Provider, defaultProvider))
	resourceType := strings.TrimSpace(firstNonEmptyString(metadata.AssetType, metadata.Service, "unknown"))
	return ruleListItem{
		ID:              metadata.ID,
		Name:            metadata.Name,
		Version:         metadata.Version,
		Description:     metadata.Description,
		Severity:        string(metadata.Severity),
		Provider:        provider,
		Service:         metadata.Service,
		ResourceType:    resourceType,
		Categories:      metadata.Categories,
		Tags:            metadata.Tags,
		Disabled:        metadata.Disabled,
		HasExamples:     len(pack.Examples) > 0 || pack.InputPath != "",
		MissingDataRefs: pack.MissingDataRefs,
		Remediation:     firstNonEmptyString(pack.Remediation, metadata.Advice),
		Link:            metadata.Link,
		Dir:             pack.Dir,
	}
}

func (h *handler) enrichFindingsWithRuleRemediation(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return findings
	}
	index := h.ruleRemediationIndex()
	if len(index) == 0 {
		return findings
	}
	output := make([]model.Finding, len(findings))
	for i, finding := range findings {
		output[i] = enrichFindingWithRuleIndex(finding, index)
	}
	return output
}

func (h *handler) enrichFindingWithRuleRemediation(finding model.Finding) model.Finding {
	return enrichFindingWithRuleIndex(finding, h.ruleRemediationIndex())
}

func (h *handler) enrichFindingViewWithRuleRemediation(finding model.FindingView) model.FindingView {
	finding.Finding = h.enrichFindingWithRuleRemediation(finding.Finding)
	return finding
}

func (h *handler) enrichAssetViewWithRuleRemediation(asset model.AssetView) model.AssetView {
	if len(asset.Findings) == 0 {
		return asset
	}
	index := h.ruleRemediationIndex()
	if len(index) == 0 {
		return asset
	}
	for i := range asset.Findings {
		asset.Findings[i].Finding = enrichFindingWithRuleIndex(asset.Findings[i].Finding, index)
	}
	return asset
}

func enrichFindingWithRuleIndex(finding model.Finding, index map[string]string) model.Finding {
	if strings.TrimSpace(finding.Remediation) != "" || len(index) == 0 {
		return finding
	}
	if remediation := index[finding.RuleID]; remediation != "" {
		finding.Remediation = remediation
		return finding
	}
	if remediation := index[strings.ToLower(strings.TrimSpace(finding.RuleID))]; remediation != "" {
		finding.Remediation = remediation
	}
	return finding
}

func (h *handler) ruleRemediationIndex() map[string]string {
	if err := ValidateRulesDir(h.rulesDir); err != nil {
		return nil
	}
	packs, err := rule.LoadDirWithOptions(h.rulesDir, rule.LoadDirOptions{IncludeDisabled: true})
	if err != nil {
		return nil
	}
	index := map[string]string{}
	for _, pack := range packs {
		id := strings.TrimSpace(pack.Metadata.ID)
		remediation := firstNonEmptyString(pack.Remediation, pack.Metadata.Advice)
		if id == "" || remediation == "" {
			continue
		}
		index[id] = remediation
		index[strings.ToLower(id)] = remediation
	}
	return index
}

func ruleMatchesFilter(item ruleListItem, filter rulesFilter) bool {
	if filter.Provider != "" && normalizeProvider(item.Provider) != filter.Provider {
		return false
	}
	if filter.ResourceType != "" && !sameResourceType(item.ResourceType, filter.ResourceType) {
		return false
	}
	if filter.Severity != "" && !strings.EqualFold(item.Severity, filter.Severity) {
		return false
	}
	if filter.RuleID != "" && item.ID != filter.RuleID {
		return false
	}
	if filter.Enabled != nil && (item.Disabled == *filter.Enabled) {
		return false
	}
	if filter.Q != "" && !ruleMatchesQuery(item, filter.Q) {
		return false
	}
	return true
}

func ruleMatchesQuery(item ruleListItem, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	values := []string{
		item.ID,
		item.Name,
		item.Description,
		item.Provider,
		item.Service,
		item.ResourceType,
		item.Severity,
		item.Remediation,
		item.Link,
	}
	values = append(values, item.Categories...)
	values = append(values, item.Tags...)
	values = append(values, item.MissingDataRefs...)
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func sortRuleList(rules []ruleListItem, sortKey string) {
	sortKey = strings.TrimSpace(sortKey)
	desc := false
	if strings.HasPrefix(sortKey, "-") {
		desc = true
		sortKey = strings.TrimPrefix(sortKey, "-")
	}
	if sortKey == "" {
		sortKey = "id"
	}
	sort.Slice(rules, func(i, j int) bool {
		compare := 0
		switch sortKey {
		case "severity":
			compare = compareInts(severityRank(rules[i].Severity), severityRank(rules[j].Severity))
		case "resource_type":
			compare = strings.Compare(rules[i].ResourceType, rules[j].ResourceType)
		case "status":
			compare = compareInts(boolToSort(rules[i].Disabled), boolToSort(rules[j].Disabled))
		case "title", "name":
			compare = strings.Compare(rules[i].Name, rules[j].Name)
		default:
			compare = strings.Compare(rules[i].ID, rules[j].ID)
		}
		if compare == 0 {
			compare = strings.Compare(rules[i].ID, rules[j].ID)
		}
		if desc {
			return compare > 0
		}
		return compare < 0
	})
}

func paginateRuleList(rules []ruleListItem, offset int, limit int) []ruleListItem {
	if offset >= len(rules) {
		return []ruleListItem{}
	}
	end := len(rules)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return rules[offset:end]
}

func boolToSort(value bool) int {
	if value {
		return 1
	}
	return 0
}

func compareInts(left int, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func coverageOptions(rulesDir string, provider string) rule.CoverageOptions {
	options := rule.CoverageOptions{
		RulesDir: rulesDir,
		Provider: provider,
	}
	if normalizeProvider(provider) == "alicloud" {
		options.Catalog = alicloudCoverageCatalog()
		options.NativeAdapters = alicloudNativeAdapterMap()
	}
	return options
}

func defaultReviewLedgerPath(rulesDir string) string {
	path := filepath.Join(rulesDir, "review-ledger.json")
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

func defaultSamplesDir(rulesDir string, provider string) string {
	provider = normalizeProvider(provider)
	if provider == "" {
		provider = defaultProvider
	}
	candidates := []string{
		filepath.Join(filepath.Dir(rulesDir), "..", "samples", provider),
		filepath.Join(filepath.Dir(rulesDir), "samples", provider),
		filepath.Join("samples", provider),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return ""
}

func alicloudCoverageCatalog() []rule.CoverageCatalogSpec {
	specs := alicloud.AllResourceSpecs()
	catalog := make([]rule.CoverageCatalogSpec, 0, len(specs))
	for _, spec := range specs {
		catalog = append(catalog, rule.CoverageCatalogSpec{
			Type:       spec.Type,
			Normalized: spec.Normalized,
			Group:      spec.Group,
			Dimension:  spec.Dimension,
		})
	}
	return catalog
}

func alicloudNativeAdapterMap() map[string]bool {
	adapters := map[string]bool{}
	for _, resourceType := range alicloud.NativeAdapterResourceTypes() {
		adapters[resourceType] = true
	}
	return adapters
}

func ValidateRulesDir(rulesDir string) error {
	rulesDir = strings.TrimSpace(rulesDir)
	if rulesDir == "" {
		return errors.New("rules directory is required")
	}
	info, err := os.Stat(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rules directory %q does not exist; pass --rules to a valid rule pack directory", rulesDir)
		}
		return fmt.Errorf("stat rules directory %q: %w", rulesDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("rules path %q is not a directory", rulesDir)
	}
	return nil
}

func firstQueryValue(r *http.Request, names ...string) string {
	for _, name := range names {
		value := strings.TrimSpace(r.URL.Query().Get(name))
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func normalizeProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	provider = strings.ReplaceAll(provider, "_", "")
	provider = strings.ReplaceAll(provider, "-", "")
	provider = strings.ReplaceAll(provider, " ", "")
	if provider == "aliyun" || provider == "alibaba" || provider == "alibabacloud" {
		return "alicloud"
	}
	return provider
}

func sameResourceType(left string, right string) bool {
	return compactResourceType(left) == compactResourceType(right)
}

func compactResourceType(resourceType string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(resourceType)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func isNotFoundError(err error) bool {
	if errors.Is(err, sql.ErrNoRows) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "not found") || strings.Contains(message, "no rows")
}

func allowMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method || (method == http.MethodGet && r.Method == http.MethodHead) {
		return true
	}
	w.Header().Set("Allow", method)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

type findingsResponse struct {
	Findings []model.Finding `json:"findings"`
	Count    int             `json:"count"`
	Total    int             `json:"total"`
	Limit    int             `json:"limit,omitempty"`
	Offset   int             `json:"offset,omitempty"`
}

type assetsResponse struct {
	Assets []model.Asset `json:"assets"`
	Count  int           `json:"count"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit,omitempty"`
	Offset int           `json:"offset,omitempty"`
}

type scanRunsResponse struct {
	ScanRuns []model.ScanRun `json:"scan_runs"`
	Count    int             `json:"count"`
	Total    int             `json:"total"`
	Limit    int             `json:"limit,omitempty"`
	Offset   int             `json:"offset,omitempty"`
}

type relationshipsResponse struct {
	Relationships []model.AssetRelationship `json:"relationships"`
	Count         int                       `json:"count"`
	Total         int                       `json:"total"`
	Limit         int                       `json:"limit,omitempty"`
	Offset        int                       `json:"offset,omitempty"`
}

type dashboardResponse struct {
	Summary        model.Summary   `json:"summary"`
	TopFindings    []model.Finding `json:"top_findings"`
	RecentScanRuns []model.ScanRun `json:"recent_scan_runs"`
	GeneratedAt    time.Time       `json:"generated_at"`
}

type facetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type facetsResponse struct {
	Providers     []facetValue `json:"providers"`
	Accounts      []facetValue `json:"accounts"`
	ResourceTypes []facetValue `json:"resource_types"`
	Regions       []facetValue `json:"regions"`
	Severities    []facetValue `json:"severities"`
	Statuses      []facetValue `json:"statuses"`
	Rules         []facetValue `json:"rules"`
	ScanStatuses  []facetValue `json:"scan_statuses"`
}

type findingDetailResponse struct {
	Finding model.Finding `json:"finding"`
}

type assetDetailResponse struct {
	Asset          model.Asset               `json:"asset"`
	ProductSummary map[string]any            `json:"product_summary,omitempty"`
	Findings       []model.Finding           `json:"findings"`
	Relationships  []model.AssetRelationship `json:"relationships"`
}

type graphResponse struct {
	Nodes         []graphNode               `json:"nodes"`
	Edges         []graphEdge               `json:"edges"`
	Relationships []model.AssetRelationship `json:"relationships"`
	Depth         int                       `json:"depth"`
	Count         int                       `json:"count"`
}

type graphNode struct {
	ID           string `json:"id"`
	AccountID    string `json:"account_id,omitempty"`
	Provider     string `json:"provider,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
}

type graphEdge struct {
	ID               string          `json:"id"`
	Source           string          `json:"source"`
	Target           string          `json:"target"`
	RelationshipType string          `json:"relationship_type"`
	Properties       json.RawMessage `json:"properties,omitempty"`
}

type ruleListItem struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Version         string   `json:"version,omitempty"`
	Description     string   `json:"description,omitempty"`
	Severity        string   `json:"severity"`
	Provider        string   `json:"provider"`
	Service         string   `json:"service,omitempty"`
	ResourceType    string   `json:"resource_type"`
	Categories      []string `json:"categories,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Disabled        bool     `json:"disabled"`
	HasExamples     bool     `json:"has_examples"`
	MissingDataRefs []string `json:"missing_data_refs,omitempty"`
	Remediation     string   `json:"remediation,omitempty"`
	Link            string   `json:"link,omitempty"`
	Dir             string   `json:"dir,omitempty"`
}

type rulesResponse struct {
	Rules    []ruleListItem `json:"rules"`
	Count    int            `json:"count"`
	Total    int            `json:"total"`
	Limit    int            `json:"limit,omitempty"`
	Offset   int            `json:"offset,omitempty"`
	RulesDir string         `json:"rules_dir"`
	Provider string         `json:"provider"`
}

type runtimeResponse struct {
	Version         string   `json:"version"`
	Provider        string   `json:"provider"`
	RulesDir        string   `json:"rules_dir"`
	DatabasePath    string   `json:"database_path,omitempty"`
	StoreConfigured bool     `json:"store_configured"`
	RulesAvailable  bool     `json:"rules_available"`
	RulesError      string   `json:"rules_error,omitempty"`
	Endpoints       []string `json:"endpoints"`
}

type errorResponse struct {
	Error string `json:"error"`
}
