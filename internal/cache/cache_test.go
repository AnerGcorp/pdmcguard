// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package cache

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "cache.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestOpen_CreatesSchema(t *testing.T) {
	store := openTestStore(t)
	// Should be able to query without error (tables exist)
	alerts, err := store.CriticalAlerts("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestUpsertAndQueryProjectAlerts(t *testing.T) {
	store := openTestStore(t)

	store.UpsertProjectAlert(ProjectAlert{
		ProjectDir:  "/home/user/myproject",
		AdvisoryID:  "GHSA-xxxx",
		PackageName: "lodash",
		Ecosystem:   "npm",
		Severity:    "critical",
		Summary:     "Prototype Pollution",
	})
	store.UpsertProjectAlert(ProjectAlert{
		ProjectDir:  "/home/user/myproject",
		AdvisoryID:  "GHSA-yyyy",
		PackageName: "express",
		Ecosystem:   "npm",
		Severity:    "high", // not critical
		Summary:     "Path Traversal",
	})
	store.UpsertProjectAlert(ProjectAlert{
		ProjectDir:  "/home/user/other",
		AdvisoryID:  "GHSA-zzzz",
		PackageName: "flask",
		Ecosystem:   "pypi",
		Severity:    "critical",
		Summary:     "SSTI",
	})

	// Query critical alerts for myproject
	alerts, err := store.CriticalAlerts("/home/user/myproject")
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 critical alert, got %d", len(alerts))
	}
	if alerts[0].PackageName != "lodash" {
		t.Errorf("expected lodash, got %s", alerts[0].PackageName)
	}

	// Query other project
	alerts2, err := store.CriticalAlerts("/home/user/other")
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts2) != 1 {
		t.Fatalf("expected 1 critical alert for other, got %d", len(alerts2))
	}
}

func TestClearProjectAlerts(t *testing.T) {
	store := openTestStore(t)

	store.UpsertProjectAlert(ProjectAlert{
		ProjectDir:  "/proj",
		AdvisoryID:  "A1",
		PackageName: "pkg",
		Ecosystem:   "npm",
		Severity:    "critical",
	})

	store.ClearProjectAlerts("/proj")

	alerts, _ := store.CriticalAlerts("/proj")
	if len(alerts) != 0 {
		t.Errorf("expected 0 after clear, got %d", len(alerts))
	}
}

func TestUpsertProjectAlert_Dedup(t *testing.T) {
	store := openTestStore(t)

	pa := ProjectAlert{
		ProjectDir:  "/proj",
		AdvisoryID:  "A1",
		PackageName: "pkg",
		Ecosystem:   "npm",
		Severity:    "critical",
		Summary:     "first",
	}
	store.UpsertProjectAlert(pa)

	pa.Summary = "updated"
	store.UpsertProjectAlert(pa)

	alerts, _ := store.CriticalAlerts("/proj")
	if len(alerts) != 1 {
		t.Fatalf("expected 1 after dedup upsert, got %d", len(alerts))
	}
	if alerts[0].Summary != "updated" {
		t.Errorf("expected updated summary, got %q", alerts[0].Summary)
	}
}

func TestMetaGetSet(t *testing.T) {
	store := openTestStore(t)

	val, err := store.GetMeta("missing")
	if err != nil {
		t.Fatal(err)
	}
	if val != "" {
		t.Errorf("expected empty for missing key, got %q", val)
	}

	store.SetMeta("last_full_sync", "2026-03-28T10:00:00Z")
	val, _ = store.GetMeta("last_full_sync")
	if val != "2026-03-28T10:00:00Z" {
		t.Errorf("expected stored value, got %q", val)
	}
}

func TestIsStale(t *testing.T) {
	store := openTestStore(t)

	// No sync recorded → stale
	if !store.IsStale(24) {
		t.Error("expected stale when no sync recorded")
	}

	// Recent sync → not stale
	store.SetMeta("last_full_sync", time.Now().UTC().Format(time.RFC3339))
	if store.IsStale(24) {
		t.Error("expected not stale after recent sync")
	}

	// Old sync → stale
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	store.SetMeta("last_full_sync", old)
	if !store.IsStale(24) {
		t.Error("expected stale after 48h with 24h TTL")
	}
}

func TestEmptyCacheReturnsNil(t *testing.T) {
	store := openTestStore(t)
	alerts, err := store.CriticalAlerts("/any/path")
	if err != nil {
		t.Fatal(err)
	}
	if alerts != nil {
		t.Errorf("expected nil for empty cache, got %v", alerts)
	}
}

// TestCriticalAlerts_RespectsQuietWindow verifies the 24h suppression
// introduced to stop the shell hook from re-printing the same banner on
// every prompt. After MarkShown, CriticalAlerts should return empty until
// last_shown_at ages past the quiet window.
func TestCriticalAlerts_RespectsQuietWindow(t *testing.T) {
	store := openTestStore(t)

	store.UpsertProjectAlert(ProjectAlert{
		ProjectDir:  "/proj",
		AdvisoryID:  "GHSA-1111",
		PackageName: "litellm",
		Ecosystem:   "pypi",
		Severity:    "critical",
		Summary:     "exposed token",
	})

	// First read: should return the alert (never shown before).
	alerts, err := store.CriticalAlerts("/proj")
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert before MarkShown, got %d", len(alerts))
	}

	// After MarkShown, the quiet window begins — next read is empty.
	if err := store.MarkShown("/proj"); err != nil {
		t.Fatal(err)
	}
	alerts, _ = store.CriticalAlerts("/proj")
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts inside quiet window, got %d", len(alerts))
	}

	// Age last_shown_at past the window and re-read — should reappear.
	old := time.Now().UTC().Add(-25 * time.Hour).Format(time.RFC3339)
	if _, err := store.db.Exec(
		`UPDATE project_alerts SET last_shown_at = ? WHERE project_dir = ?`, old, "/proj",
	); err != nil {
		t.Fatal(err)
	}
	alerts, _ = store.CriticalAlerts("/proj")
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert after quiet window expires, got %d", len(alerts))
	}
}

// TestUpsertPreservesLastShownAt guards against a subtle regression: if
// UpsertProjectAlert used INSERT OR REPLACE instead of UPSERT-with-preserve,
// every daemon re-sync would reset the quiet window and the hook would
// spam again on the next prompt.
func TestUpsertPreservesLastShownAt(t *testing.T) {
	store := openTestStore(t)

	pa := ProjectAlert{
		ProjectDir:  "/proj",
		AdvisoryID:  "GHSA-2222",
		PackageName: "lodash",
		Ecosystem:   "npm",
		Severity:    "critical",
		Summary:     "old",
	}
	store.UpsertProjectAlert(pa)
	store.MarkShown("/proj")

	// Re-upsert (simulates a daemon re-sync).
	pa.Summary = "new"
	store.UpsertProjectAlert(pa)

	// Alert should stay suppressed by the original MarkShown.
	alerts, _ := store.CriticalAlerts("/proj")
	if len(alerts) != 0 {
		t.Errorf("expected upsert to preserve last_shown_at (got %d alerts)", len(alerts))
	}

	// And the summary should still be updated (upsert still writes the row).
	var summary string
	if err := store.db.QueryRow(
		`SELECT summary FROM project_alerts WHERE project_dir = ? AND advisory_id = ?`,
		"/proj", "GHSA-2222",
	).Scan(&summary); err != nil {
		t.Fatal(err)
	}
	if summary != "new" {
		t.Errorf("expected summary 'new', got %q", summary)
	}
}

// TestHasAnyCritical exercises the signal the sync engine uses to
// write/remove the ~/.pdmcguard/alerts.flag sentinel file.
func TestHasAnyCritical(t *testing.T) {
	store := openTestStore(t)

	any, err := store.HasAnyCritical()
	if err != nil {
		t.Fatal(err)
	}
	if any {
		t.Error("expected false for empty cache")
	}

	store.UpsertProjectAlert(ProjectAlert{
		ProjectDir: "/a", AdvisoryID: "X", PackageName: "p",
		Ecosystem: "npm", Severity: "critical",
	})
	if any, _ = store.HasAnyCritical(); !any {
		t.Error("expected true after inserting a critical alert")
	}

	// Non-critical row alone should not flip the signal.
	store.ClearProjectAlerts("/a")
	store.UpsertProjectAlert(ProjectAlert{
		ProjectDir: "/a", AdvisoryID: "Y", PackageName: "p",
		Ecosystem: "npm", Severity: "high",
	})
	if any, _ = store.HasAnyCritical(); any {
		t.Error("expected false when only non-critical rows remain")
	}
}

// TestUpsert_CanonicalizesTrailingSlash guards the composite PRIMARY KEY
// against trailing-slash drift. Without canonicalization, "/tmp/foo/" and
// "/tmp/foo" would key as distinct rows and the same logical project could
// accumulate duplicate alerts — a real bug observed during Stage 1 verify.
func TestUpsert_CanonicalizesTrailingSlash(t *testing.T) {
	store := openTestStore(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	base := ProjectAlert{
		AdvisoryID:  "GHSA-SLASH",
		PackageName: "pkg",
		Ecosystem:   "npm",
		Severity:    "critical",
		Summary:     "first",
	}

	// Upsert once with a trailing slash, then with the clean form.
	withSlash := base
	withSlash.ProjectDir = dir + "/"
	if err := store.UpsertProjectAlert(withSlash); err != nil {
		t.Fatal(err)
	}

	clean := base
	clean.ProjectDir = dir
	clean.Summary = "second"
	if err := store.UpsertProjectAlert(clean); err != nil {
		t.Fatal(err)
	}

	// Count rows directly — CriticalAlerts also canonicalizes, which would
	// hide the duplicate. Hit the table directly.
	var n int
	if err := store.db.QueryRow(
		`SELECT COUNT(*) FROM project_alerts WHERE advisory_id = ?`,
		"GHSA-SLASH",
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row after slash/no-slash upserts, got %d", n)
	}

	// The second upsert should have won (upsert semantics).
	alerts, _ := store.CriticalAlerts(dir)
	if len(alerts) != 1 || alerts[0].Summary != "second" {
		t.Errorf("expected summary 'second', got %+v", alerts)
	}
}

// TestUpsert_CanonicalizesSymlink covers the daemon-vs-shell-hook case:
// the watcher sees the symlink-resolved path while the shell hook reports
// the symlinked path from os.Getwd. Without canonicalization those rows
// diverge and CriticalAlerts misses half of them.
func TestUpsert_CanonicalizesSymlink(t *testing.T) {
	store := openTestStore(t)
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(tmp, "real")
	linkDir := filepath.Join(tmp, "link")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}

	// Upsert via the symlinked path.
	if err := store.UpsertProjectAlert(ProjectAlert{
		ProjectDir:  linkDir,
		AdvisoryID:  "GHSA-SYM",
		PackageName: "pkg",
		Ecosystem:   "npm",
		Severity:    "critical",
		Summary:     "sym",
	}); err != nil {
		t.Fatal(err)
	}

	// Query via the resolved path — should see the same row.
	alerts, err := store.CriticalAlerts(realDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert when querying resolved path, got %d", len(alerts))
	}
	if alerts[0].AdvisoryID != "GHSA-SYM" {
		t.Errorf("unexpected advisory id: %q", alerts[0].AdvisoryID)
	}

	// Second upsert via the resolved path must not create a duplicate row.
	if err := store.UpsertProjectAlert(ProjectAlert{
		ProjectDir:  realDir,
		AdvisoryID:  "GHSA-SYM",
		PackageName: "pkg",
		Ecosystem:   "npm",
		Severity:    "critical",
		Summary:     "sym2",
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := store.db.QueryRow(
		`SELECT COUNT(*) FROM project_alerts WHERE advisory_id = ?`,
		"GHSA-SYM",
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected single canonical row, got %d", n)
	}
}

// TestMigration_LastShownAtColumnAdded opens a DB created under the old
// schema (no last_shown_at column) and verifies that Open() applies the
// additive migration without touching existing rows.
func TestMigration_LastShownAtColumnAdded(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "old.db")

	// Simulate the pre-migration schema.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE project_alerts (
			project_dir  TEXT NOT NULL,
			advisory_id  TEXT NOT NULL,
			package_name TEXT NOT NULL,
			ecosystem    TEXT NOT NULL,
			severity     TEXT NOT NULL,
			summary      TEXT NOT NULL DEFAULT '',
			updated_at   TEXT NOT NULL,
			PRIMARY KEY (project_dir, advisory_id)
		);
		INSERT INTO project_alerts VALUES ('/old', 'A', 'pkg', 'npm', 'critical', '', '2026-01-01T00:00:00Z');
	`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// Re-open through the real constructor — migration should run.
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open should migrate cleanly: %v", err)
	}
	defer store.Close()

	// Column must now exist.
	rows, err := store.db.Query(`PRAGMA table_info(project_alerts)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var found bool
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if strings.EqualFold(name, "last_shown_at") {
			found = true
		}
	}
	if !found {
		t.Error("migration did not add last_shown_at column")
	}

	// Existing row must survive untouched.
	alerts, _ := store.CriticalAlerts("/old")
	if len(alerts) != 1 {
		t.Errorf("expected 1 pre-existing alert post-migration, got %d", len(alerts))
	}
}
