// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package sync

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const queueSchema = `
CREATE TABLE IF NOT EXISTS sync_queue (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	project_dir TEXT NOT NULL,
	lock_path   TEXT NOT NULL,
	ecosystem   TEXT NOT NULL,
	git_branch  TEXT NOT NULL DEFAULT '',
	git_commit  TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL
);
`

const queuePragmas = `
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
`

const maxQueueAge = 7 * 24 * time.Hour // 7 days

// QueueItem represents a pending sync operation.
type QueueItem struct {
	ID         int64
	ProjectDir string
	LockPath   string
	Ecosystem  string
	GitBranch  string
	GitCommit  string
	CreatedAt  time.Time
}

// Queue stores pending sync operations for offline resilience.
type Queue struct {
	db *sql.DB
}

// OpenQueue opens (or creates) the offline sync queue.
func OpenQueue(path string) (*Queue, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open queue db: %w", err)
	}
	if _, err := db.Exec(queuePragmas); err != nil {
		db.Close()
		return nil, fmt.Errorf("set queue pragmas: %w", err)
	}
	if _, err := db.Exec(queueSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create queue schema: %w", err)
	}
	return &Queue{db: db}, nil
}

// Close closes the queue database.
func (q *Queue) Close() error {
	return q.db.Close()
}

// Enqueue adds a sync item to the offline queue.
func (q *Queue) Enqueue(item QueueItem) error {
	_, err := q.db.Exec(
		`INSERT INTO sync_queue (project_dir, lock_path, ecosystem, git_branch, git_commit, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		item.ProjectDir, item.LockPath, item.Ecosystem,
		item.GitBranch, item.GitCommit,
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// Drain returns and removes all non-expired items from the queue, oldest first.
func (q *Queue) Drain() ([]QueueItem, error) {
	cutoff := time.Now().Add(-maxQueueAge).UTC().Format(time.RFC3339)

	// Delete expired items first
	if _, err := q.db.Exec(`DELETE FROM sync_queue WHERE created_at < ?`, cutoff); err != nil {
		return nil, err
	}

	rows, err := q.db.Query(
		`SELECT id, project_dir, lock_path, ecosystem, git_branch, git_commit, created_at
		 FROM sync_queue ORDER BY id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []QueueItem
	for rows.Next() {
		var item QueueItem
		var ts string
		if err := rows.Scan(&item.ID, &item.ProjectDir, &item.LockPath, &item.Ecosystem,
			&item.GitBranch, &item.GitCommit, &ts); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = time.Parse(time.RFC3339, ts)
		items = append(items, item)
	}

	// Remove drained items
	if len(items) > 0 {
		if _, err := q.db.Exec(`DELETE FROM sync_queue`); err != nil {
			return items, err
		}
	}

	return items, rows.Err()
}

// Len returns the number of items in the queue.
func (q *Queue) Len() (int, error) {
	var n int
	err := q.db.QueryRow(`SELECT COUNT(*) FROM sync_queue`).Scan(&n)
	return n, err
}
