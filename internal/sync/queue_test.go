// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package sync

import (
	"path/filepath"
	"testing"
)

func TestQueueEnqueueAndDrain(t *testing.T) {
	dir := t.TempDir()
	q, err := OpenQueue(filepath.Join(dir, "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Enqueue 3 items
	for i, name := range []string{"project-a", "project-b", "project-c"} {
		err := q.Enqueue(QueueItem{
			ProjectDir: "/home/user/" + name,
			LockPath:   "/home/user/" + name + "/go.sum",
			Ecosystem:  "go",
			GitBranch:  "main",
			GitCommit:  "abc123",
		})
		if err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	// Verify count
	n, err := q.Len()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected 3 items, got %d", n)
	}

	// Drain
	items, err := q.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 drained items, got %d", len(items))
	}

	// Should be ordered by ID (oldest first)
	if items[0].ProjectDir != "/home/user/project-a" {
		t.Errorf("first item = %q, want project-a", items[0].ProjectDir)
	}
	if items[2].ProjectDir != "/home/user/project-c" {
		t.Errorf("last item = %q, want project-c", items[2].ProjectDir)
	}

	// Queue should be empty after drain
	n, err = q.Len()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expected 0 items after drain, got %d", n)
	}
}

func TestQueueDrainEmpty(t *testing.T) {
	dir := t.TempDir()
	q, err := OpenQueue(filepath.Join(dir, "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	items, err := q.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("expected 0 items from empty queue, got %d", len(items))
	}
}

func TestQueuePersistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "queue.db")

	// Open, enqueue, close
	q1, err := OpenQueue(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = q1.Enqueue(QueueItem{
		ProjectDir: "/test/project",
		LockPath:   "/test/project/package-lock.json",
		Ecosystem:  "npm",
	})
	q1.Close()

	// Reopen, verify item persists
	q2, err := OpenQueue(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()

	n, err := q2.Len()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 persisted item, got %d", n)
	}
}
