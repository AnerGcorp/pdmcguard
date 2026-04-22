// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AnerGcorp/pdmcguard/internal/cache"
	"github.com/AnerGcorp/pdmcguard/internal/excludes"
)

// setupExcludeHarness stands up a fresh matcher + cache store pair in a
// temp dir and rewires the package-level vars (openMatcher /
// openExcludeCacheStore) so runExclude/runUnexclude operate against
// them. The harness returns the rules-file path and the store for
// direct assertions.
func setupExcludeHarness(t *testing.T) (rulesPath string, store *cache.Store) {
	t.Helper()
	dir := t.TempDir()
	rulesPath = filepath.Join(dir, "excludes")
	dbPath := filepath.Join(dir, "cache.db")

	var err error
	store, err = cache.Open(dbPath)
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	origMatcher := openMatcher
	origStore := openExcludeCacheStore
	openMatcher = func() (*excludes.Matcher, error) {
		return excludes.Load(rulesPath)
	}
	openExcludeCacheStore = func() (*cache.Store, error) {
		// Return a fresh handle to the same DB so defer store.Close in
		// wipeMatchedRows doesn't close the test-owned handle.
		return cache.Open(dbPath)
	}
	t.Cleanup(func() {
		openMatcher = origMatcher
		openExcludeCacheStore = origStore
	})
	return rulesPath, store
}

// TestExclude_PersistsRuleAndWipesCache is the headline integration
// test: a user excludes a monorepo subtree; the rule lands on disk,
// project_alerts rows under that subtree vanish, project_acks rows
// under the subtree vanish, but unrelated rows survive.
func TestExclude_PersistsRuleAndWipesCache(t *testing.T) {
	rulesPath, store := setupExcludeHarness(t)

	keep := "/home/user/kept-proj"
	drop := "/home/user/legacy/pkg-a"
	store.UpsertProjectAlert(cache.ProjectAlert{
		ProjectDir: keep, AdvisoryID: "A1", PackageName: "x",
		Ecosystem: "npm", Severity: "critical",
	})
	store.UpsertProjectAlert(cache.ProjectAlert{
		ProjectDir: drop, AdvisoryID: "A2", PackageName: "y",
		Ecosystem: "npm", Severity: "critical",
	})
	if err := store.Ack(drop, "A2"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ack(cache.GlobalAckScope, "A-global"); err != nil {
		t.Fatal(err)
	}

	m, err := excludes.Load(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Add("/home/user/legacy"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	n, err := wipeMatchedRows(m)
	if err != nil {
		t.Fatalf("wipeMatchedRows: %v", err)
	}
	if n != 1 {
		t.Errorf("wiped count = %d, want 1", n)
	}

	// Verify: rule is persisted on disk.
	data, _ := os.ReadFile(rulesPath)
	if string(data) != "/home/user/legacy\n" {
		t.Errorf("rule file = %q, want %q", string(data), "/home/user/legacy\n")
	}

	// Verify: dropped project's alerts gone, kept project's alerts
	// survive, global ack survives, per-project ack gone.
	if alerts, _ := store.CriticalAlerts(drop); len(alerts) != 0 {
		t.Errorf("expected dropped project to have 0 alerts, got %d", len(alerts))
	}
	if alerts, _ := store.CriticalAlerts(keep); len(alerts) != 1 {
		t.Errorf("kept project should still have 1 alert, got %d", len(alerts))
	}
	acks, _ := store.ListAcks()
	var sawGlobal, sawDropAck bool
	for _, a := range acks {
		if a.ProjectDir == cache.GlobalAckScope {
			sawGlobal = true
		}
		if a.ProjectDir == drop {
			sawDropAck = true
		}
	}
	if !sawGlobal {
		t.Error("global ack should survive exclude cleanup")
	}
	if sawDropAck {
		t.Error("per-project ack under excluded subtree should be gone")
	}
}

// TestExclude_Basename verifies wipeMatchedRows works for basename
// tokens too (e.g. `node_modules`): every project_dir with that
// component in its path gets cleared.
func TestExclude_Basename(t *testing.T) {
	rulesPath, store := setupExcludeHarness(t)

	store.UpsertProjectAlert(cache.ProjectAlert{
		ProjectDir: "/a/legitimate-project", AdvisoryID: "A1",
		PackageName: "x", Ecosystem: "npm", Severity: "critical",
	})
	// Path contains a "fixtures" component — simulates a weird project
	// living under a test-fixture tree we want to silence.
	store.UpsertProjectAlert(cache.ProjectAlert{
		ProjectDir: "/a/fixtures/sub", AdvisoryID: "A2",
		PackageName: "y", Ecosystem: "npm", Severity: "critical",
	})

	m, err := excludes.Load(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Add("fixtures"); err != nil {
		t.Fatal(err)
	}

	if _, err := wipeMatchedRows(m); err != nil {
		t.Fatal(err)
	}

	if alerts, _ := store.CriticalAlerts("/a/fixtures/sub"); len(alerts) != 0 {
		t.Error("fixtures subtree should be wiped")
	}
	if alerts, _ := store.CriticalAlerts("/a/legitimate-project"); len(alerts) != 1 {
		t.Error("unrelated project should survive")
	}
}

// TestNormalizeRule exercises the path-resolution branches users hit
// in practice. The key regression guard is the bare-relative-with-slash
// rejection: `foo/bar` is ambiguous between "relative path" and
// "pattern" and must error, forcing the user to disambiguate with `./`
// or `/`. Previously this silently cwd-joined, which produced rules
// that didn't match what appeared on --list.
func TestNormalizeRule(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cases := []struct {
		name, in string
		want     string
		wantErr  bool
	}{
		{"tilde", "~/foo/bar", filepath.Join(home, "foo", "bar"), false},
		{"basename", "node_modules", "node_modules", false},
		{"empty", "", "", true},
		{"bare-relative-with-slash", "some/relative/with/slashes", "", true},
		{"explicit-dot-slash", "./packages/legacy", "", false}, // resolves; want non-empty
		{"absolute", "/opt/only", "/opt/only", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeRule(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("normalizeRule(%q): expected error, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Errorf("normalizeRule(%q): unexpected error %v", tc.in, err)
				return
			}
			if tc.want != "" && got != tc.want {
				t.Errorf("normalizeRule(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if tc.want == "" && got == "" {
				t.Errorf("normalizeRule(%q): expected non-empty resolved path", tc.in)
			}
		})
	}
}
