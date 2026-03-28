// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cache manages the local SQLite critical advisory cache.
package cache

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const cacheSchema = `
CREATE TABLE IF NOT EXISTS project_alerts (
	project_dir  TEXT NOT NULL,
	advisory_id  TEXT NOT NULL,
	package_name TEXT NOT NULL,
	ecosystem    TEXT NOT NULL,
	severity     TEXT NOT NULL,
	summary      TEXT NOT NULL DEFAULT '',
	updated_at   TEXT NOT NULL,
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
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// CriticalAlerts returns all critical-severity alerts for a project directory.
func (s *Store) CriticalAlerts(projectDir string) ([]Alert, error) {
	rows, err := s.db.Query(
		`SELECT advisory_id, package_name, ecosystem, severity, summary
		 FROM project_alerts
		 WHERE project_dir = ? AND severity = 'critical'
		 ORDER BY package_name`,
		projectDir,
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

// UpsertProjectAlert inserts or replaces a project alert.
func (s *Store) UpsertProjectAlert(pa ProjectAlert) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO project_alerts (project_dir, advisory_id, package_name, ecosystem, severity, summary, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
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
