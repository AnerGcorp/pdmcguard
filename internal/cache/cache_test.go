// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package cache

import (
	"path/filepath"
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
