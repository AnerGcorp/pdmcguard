// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package classifier

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS excluded_inodes (
	inode        INTEGER PRIMARY KEY,
	kind         INTEGER NOT NULL,
	original_path TEXT NOT NULL,
	created_at   TEXT NOT NULL
);
`

const pragmas = `
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
`

// ExcludeStore persists inode-based directory exclusions in a local SQLite DB.
type ExcludeStore struct {
	db *sql.DB
}

// OpenExcludeStore opens (or creates) the excludes database at the given path.
func OpenExcludeStore(path string) (*ExcludeStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open excludes db: %w", err)
	}
	if _, err := db.Exec(pragmas); err != nil {
		db.Close()
		return nil, fmt.Errorf("set pragmas: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &ExcludeStore{db: db}, nil
}

// Add records a directory exclusion by its inode.
func (s *ExcludeStore) Add(inode uint64, kind DirKind, path string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO excluded_inodes (inode, kind, original_path, created_at) VALUES (?, ?, ?, ?)`,
		inode, int(kind), path, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// IsExcluded returns true if the given inode is in the exclusion list.
func (s *ExcludeStore) IsExcluded(inode uint64) bool {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM excluded_inodes WHERE inode = ?`, inode).Scan(&count)
	return err == nil && count > 0
}

// Remove deletes an exclusion by inode.
func (s *ExcludeStore) Remove(inode uint64) error {
	_, err := s.db.Exec(`DELETE FROM excluded_inodes WHERE inode = ?`, inode)
	return err
}

// Close closes the underlying database.
func (s *ExcludeStore) Close() error {
	return s.db.Close()
}
