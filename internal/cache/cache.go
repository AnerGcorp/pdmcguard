// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cache manages the local SQLite critical advisory cache.
package cache

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// QuietWindow is how long a critical alert is suppressed after being shown
// once in a terminal. Prevents the shell hook from re-printing on every
// directory change within the same day.
const QuietWindow = 24 * time.Hour

const cacheSchema = `
CREATE TABLE IF NOT EXISTS project_alerts (
	project_dir   TEXT NOT NULL,
	advisory_id   TEXT NOT NULL,
	package_name  TEXT NOT NULL,
	ecosystem     TEXT NOT NULL,
	severity      TEXT NOT NULL,
	summary       TEXT NOT NULL DEFAULT '',
	updated_at    TEXT NOT NULL,
	last_shown_at TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (project_dir, advisory_id)
);

CREATE INDEX IF NOT EXISTS idx_project_alerts_dir
	ON project_alerts (project_dir);

CREATE TABLE IF NOT EXISTS advisories (
	id            TEXT PRIMARY KEY,
	package_name  TEXT NOT NULL,
	ecosystem     TEXT NOT NULL,
	severity      TEXT NOT NULL,
	summary       TEXT NOT NULL DEFAULT '',
	source        TEXT NOT NULL DEFAULT '',
	external_id   TEXT NOT NULL DEFAULT '',
	introduced    TEXT NOT NULL DEFAULT '',
	fixed         TEXT NOT NULL DEFAULT '',
	last_affected TEXT NOT NULL DEFAULT '',
	published_at  TEXT NOT NULL DEFAULT '',
	synced_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_advisories_pkg_eco
	ON advisories (package_name, ecosystem);

CREATE TABLE IF NOT EXISTS cache_meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_acks (
	project_dir  TEXT NOT NULL,
	advisory_id  TEXT NOT NULL,
	acked_at     TEXT NOT NULL,
	PRIMARY KEY (project_dir, advisory_id)
);
`

const cachePragmas = `
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
`

// Alert is a lightweight projection of a project alert for display.
type Alert struct {
	AdvisoryID  string
	PackageName string
	Ecosystem   string
	Severity    string
	Summary     string
}

// ProjectAlert represents a pre-computed alert for a project directory.
type ProjectAlert struct {
	ProjectDir  string
	AdvisoryID  string
	PackageName string
	Ecosystem   string
	Severity    string
	Summary     string
}

// Advisory holds full advisory data synced from Supabase.
type Advisory struct {
	ID           string
	PackageName  string
	Ecosystem    string
	Severity     string
	Summary      string
	Source       string
	ExternalID   string
	Introduced   string
	Fixed        string
	LastAffected string
	PublishedAt  string
	SyncedAt     time.Time
}

// Store provides read/write access to the local advisory cache.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the cache database at the given path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open cache db: %w", err)
	}
	if _, err := db.Exec(cachePragmas); err != nil {
		db.Close()
		return nil, fmt.Errorf("set pragmas: %w", err)
	}
	if _, err := db.Exec(cacheSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	// Additive migration for caches created before last_shown_at existed.
	// SQLite returns "duplicate column name" when the column is already
	// present — that's the expected no-op path and is ignored.
	if _, err := db.Exec(`ALTER TABLE project_alerts ADD COLUMN last_shown_at TEXT NOT NULL DEFAULT ''`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			db.Close()
			return nil, fmt.Errorf("migrate last_shown_at: %w", err)
		}
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// canonProjectDir normalizes a project path for stable keying: resolve
// symlinks (best-effort) then lexically clean. Falls back to Clean on
// resolution failure so paths for removed projects still match what was
// inserted. Empty string passes through unchanged.
//
// Without this, /tmp/foo, /tmp/foo/, and /private/tmp/foo (the macOS
// symlink-resolved form) all keyed as distinct rows under the composite
// PRIMARY KEY, allowing the same logical project to accumulate duplicate
// alerts — a real bug observed during Stage 1 verification.
func canonProjectDir(p string) string {
	if p == "" {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return filepath.Clean(p)
}

// CriticalAlerts returns critical-severity alerts for a project directory
// that have not been shown in a terminal within the quiet window (24h).
// Once MarkShown has been called for the project, subsequent calls return
// an empty slice until the window elapses — this is what stops the shell
// hook from re-printing the same banner every prompt.
func (s *Store) CriticalAlerts(projectDir string) ([]Alert, error) {
	projectDir = canonProjectDir(projectDir)
	cutoff := time.Now().UTC().Add(-QuietWindow).Format(time.RFC3339)
	rows, err := s.db.Query(
		`SELECT advisory_id, package_name, ecosystem, severity, summary
		 FROM project_alerts
		 WHERE project_dir = ?
		   AND severity = 'critical'
		   AND (last_shown_at = '' OR last_shown_at < ?)
		   AND NOT EXISTS (
		     SELECT 1 FROM project_acks
		     WHERE project_acks.advisory_id = project_alerts.advisory_id
		       AND (project_acks.project_dir = project_alerts.project_dir
		            OR project_acks.project_dir = '*')
		   )
		 ORDER BY package_name`,
		projectDir, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.AdvisoryID, &a.PackageName, &a.Ecosystem, &a.Severity, &a.Summary); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// MarkShown stamps all critical alerts for projectDir with the current time.
// Call this after successfully printing the shell-hook warning to start the
// 24h quiet window (see CriticalAlerts).
func (s *Store) MarkShown(projectDir string) error {
	projectDir = canonProjectDir(projectDir)
	_, err := s.db.Exec(
		`UPDATE project_alerts
		 SET last_shown_at = ?
		 WHERE project_dir = ? AND severity = 'critical'`,
		time.Now().UTC().Format(time.RFC3339), projectDir,
	)
	return err
}

// HasAnyCritical reports whether any critical alert exists anywhere in the
// cache, across all projects, that is NOT suppressed by a project- or
// global-scoped ack. The sync engine uses this to maintain a zero-cost
// sentinel file (alerts.flag) that the shell hook can stat() to avoid
// forking the Go binary when there's nothing to show on the machine — so
// a fully-acked machine clears the flag and goes silent without ever
// invoking the ack filter at banner time.
//
// Uses EXISTS + LIMIT 1 (via SELECT 1 ... LIMIT 1) rather than COUNT(*)
// so a machine with 10k acked rows stops at the first un-acked hit.
func (s *Store) HasAnyCritical() (bool, error) {
	var one int
	err := s.db.QueryRow(
		`SELECT 1 FROM project_alerts
		 WHERE severity = 'critical'
		   AND NOT EXISTS (
		     SELECT 1 FROM project_acks
		     WHERE project_acks.advisory_id = project_alerts.advisory_id
		       AND (project_acks.project_dir = project_alerts.project_dir
		            OR project_acks.project_dir = '*')
		   )
		 LIMIT 1`,
	).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// UpsertProjectAlert inserts a new project alert or updates an existing one.
// Uses ON CONFLICT DO UPDATE (not INSERT OR REPLACE) so that last_shown_at is
// preserved across re-syncs — otherwise every advisory pull would reset the
// quiet window and the shell hook would re-print on the next prompt.
func (s *Store) UpsertProjectAlert(pa ProjectAlert) error {
	pa.ProjectDir = canonProjectDir(pa.ProjectDir)
	_, err := s.db.Exec(
		`INSERT INTO project_alerts
		   (project_dir, advisory_id, package_name, ecosystem, severity, summary, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project_dir, advisory_id) DO UPDATE SET
		   package_name = excluded.package_name,
		   ecosystem    = excluded.ecosystem,
		   severity     = excluded.severity,
		   summary      = excluded.summary,
		   updated_at   = excluded.updated_at`,
		pa.ProjectDir, pa.AdvisoryID, pa.PackageName, pa.Ecosystem, pa.Severity, pa.Summary,
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// ClearProjectAlerts removes all alerts for a project directory.
func (s *Store) ClearProjectAlerts(projectDir string) error {
	projectDir = canonProjectDir(projectDir)
	_, err := s.db.Exec(`DELETE FROM project_alerts WHERE project_dir = ?`, projectDir)
	return err
}

// ClearProjectAcks removes every ack row for projectDir. Companion to
// ClearProjectAlerts — called when we stop tracking a project (e.g. the
// user ran `pdmcguard exclude`) so the ack table doesn't accumulate
// tombstones for paths we'll never see again.
//
// Global acks (project_dir = "*") are never touched: canonProjectDir
// rewrites "*" into an absolute path and the WHERE clause would no
// longer match. That's the intended behavior — a global ack should
// survive per-project excludes.
func (s *Store) ClearProjectAcks(projectDir string) error {
	projectDir = canonProjectDir(projectDir)
	_, err := s.db.Exec(`DELETE FROM project_acks WHERE project_dir = ?`, projectDir)
	return err
}

// ListProjectDirs returns every distinct project_dir currently carrying
// alerts. Used by the exclude CLI to find what subtrees to wipe when a
// new rule matches existing rows. Ordered for deterministic CLI output.
func (s *Store) ListProjectDirs() ([]string, error) {
	rows, err := s.db.Query(
		`SELECT DISTINCT project_dir FROM project_alerts ORDER BY project_dir`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dirs []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		dirs = append(dirs, d)
	}
	return dirs, rows.Err()
}

// GlobalAckScope is the sentinel project_dir value for acks that apply
// everywhere. Callers wanting a global ack pass this explicitly — we reject
// empty strings to avoid a cwd-inherited "" accidentally becoming global.
const GlobalAckScope = "*"

// Ack represents a permanent dismissal of an advisory at a given scope.
type Ack struct {
	ProjectDir string // "*" for global
	AdvisoryID string
	AckedAt    time.Time
}

// Ack records a permanent dismissal for (projectDir, advisoryID). If
// projectDir is GlobalAckScope ("*") the ack applies across every project;
// otherwise it is scoped to the canonicalized project path. Empty
// projectDir is rejected to prevent accidental global acks from callers
// that forgot to resolve cwd.
//
// Lives on its own table (project_acks) rather than a column of
// project_alerts because syncProject wipes project_alerts rows via
// ClearProjectAlerts on every re-sync — a column would be deleted with
// the row. The separate table survives re-classification cycles.
func (s *Store) Ack(projectDir, advisoryID string) error {
	if projectDir == "" {
		return fmt.Errorf("ack: projectDir must be non-empty (use GlobalAckScope for global)")
	}
	if advisoryID == "" {
		return fmt.Errorf("ack: advisoryID must be non-empty")
	}
	if projectDir != GlobalAckScope {
		projectDir = canonProjectDir(projectDir)
	}
	_, err := s.db.Exec(
		`INSERT INTO project_acks (project_dir, advisory_id, acked_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(project_dir, advisory_id) DO UPDATE SET
		   acked_at = excluded.acked_at`,
		projectDir, advisoryID, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// Unack removes a previously-recorded ack. No-op if the row does not exist.
// projectDir is canonicalized the same way as Ack — callers pass
// GlobalAckScope for a global unack.
func (s *Store) Unack(projectDir, advisoryID string) error {
	if projectDir == "" {
		return fmt.Errorf("unack: projectDir must be non-empty (use GlobalAckScope for global)")
	}
	if projectDir != GlobalAckScope {
		projectDir = canonProjectDir(projectDir)
	}
	_, err := s.db.Exec(
		`DELETE FROM project_acks WHERE project_dir = ? AND advisory_id = ?`,
		projectDir, advisoryID,
	)
	return err
}

// ListAcks returns every ack row, ordered by project_dir then advisory_id
// for deterministic output. Used by `pdmcguard ack --list`.
func (s *Store) ListAcks() ([]Ack, error) {
	rows, err := s.db.Query(
		`SELECT project_dir, advisory_id, acked_at
		 FROM project_acks
		 ORDER BY project_dir, advisory_id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var acks []Ack
	for rows.Next() {
		var a Ack
		var ackedAt string
		if err := rows.Scan(&a.ProjectDir, &a.AdvisoryID, &ackedAt); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339, ackedAt); perr == nil {
			a.AckedAt = t
		}
		acks = append(acks, a)
	}
	return acks, rows.Err()
}

// AdvisoryIsActive reports whether advisoryID appears on any project_alerts
// row. Used by the ack CLI to warn on probable typos without refusing the
// ack — prophylactic acks are allowed.
func (s *Store) AdvisoryIsActive(advisoryID string) (bool, error) {
	var one int
	err := s.db.QueryRow(
		`SELECT 1 FROM project_alerts WHERE advisory_id = ? LIMIT 1`,
		advisoryID,
	).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// UpsertAdvisory inserts or replaces a full advisory record.
func (s *Store) UpsertAdvisory(a Advisory) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO advisories
		 (id, package_name, ecosystem, severity, summary, source, external_id, introduced, fixed, last_affected, published_at, synced_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.PackageName, a.Ecosystem, a.Severity, a.Summary, a.Source, a.ExternalID,
		a.Introduced, a.Fixed, a.LastAffected, a.PublishedAt,
		a.SyncedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// SetMeta sets a metadata key-value pair.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO cache_meta (key, value) VALUES (?, ?)`,
		key, value,
	)
	return err
}

// GetMeta retrieves a metadata value by key. Returns "" if not found.
func (s *Store) GetMeta(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM cache_meta WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// IsStale returns true if the cache has not been synced within the given TTL.
func (s *Store) IsStale(ttlHours int) bool {
	val, err := s.GetMeta("last_full_sync")
	if err != nil || val == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return true
	}
	return time.Since(t) > time.Duration(ttlHours)*time.Hour
}
