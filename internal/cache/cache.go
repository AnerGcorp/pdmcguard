// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cache manages the local SQLite critical advisory cache.
package cache

import (
	"database/sql"
	"fmt"
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

// CriticalAlerts returns critical-severity alerts for a project directory
// that have not been shown in a terminal within the quiet window (24h).
// Once MarkShown has been called for the project, subsequent calls return
// an empty slice until the window elapses — this is what stops the shell
// hook from re-printing the same banner every prompt.
func (s *Store) CriticalAlerts(projectDir string) ([]Alert, error) {
	cutoff := time.Now().UTC().Add(-QuietWindow).Format(time.RFC3339)
	rows, err := s.db.Query(
		`SELECT advisory_id, package_name, ecosystem, severity, summary
		 FROM project_alerts
		 WHERE project_dir = ?
		   AND severity = 'critical'
		   AND (last_shown_at = '' OR last_shown_at < ?)
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
	_, err := s.db.Exec(
		`UPDATE project_alerts
		 SET last_shown_at = ?
		 WHERE project_dir = ? AND severity = 'critical'`,
		time.Now().UTC().Format(time.RFC3339), projectDir,
	)
	return err
}

// HasAnyCritical reports whether any critical alert exists anywhere in the
// cache, across all projects. The sync engine uses this to maintain a
// zero-cost sentinel file (alerts.flag) that the shell hook can stat() to
// avoid forking the Go binary when there's nothing to show on the machine.
func (s *Store) HasAnyCritical() (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM project_alerts WHERE severity = 'critical'`,
	).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// UpsertProjectAlert inserts a new project alert or updates an existing one.
// Uses ON CONFLICT DO UPDATE (not INSERT OR REPLACE) so that last_shown_at is
// preserved across re-syncs — otherwise every advisory pull would reset the
// quiet window and the shell hook would re-print on the next prompt.
func (s *Store) UpsertProjectAlert(pa ProjectAlert) error {
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
	_, err := s.db.Exec(`DELETE FROM project_alerts WHERE project_dir = ?`, projectDir)
	return err
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
