// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package bootstrap

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/AnerGcorp/pdmcguard/internal/classifier"
	"github.com/AnerGcorp/pdmcguard/internal/excludes"
)

func TestScan_FindsProjectDirs(t *testing.T) {
	root := t.TempDir()

	// Create a project with go.mod
	proj := filepath.Join(root, "myproject")
	os.MkdirAll(proj, 0o755)
	os.WriteFile(filepath.Join(proj, "go.mod"), []byte("module test"), 0o644)
	os.WriteFile(filepath.Join(proj, "main.go"), []byte("package main"), 0o644)

	// Create a nested project with package.json
	nested := filepath.Join(root, "apps", "frontend")
	os.MkdirAll(nested, 0o755)
	os.WriteFile(filepath.Join(nested, "package.json"), []byte("{}"), 0o644)

	dirs, err := Scan(nil, nil, []string{root})
	if err != nil {
		t.Fatal(err)
	}

	if len(dirs) != 2 {
		t.Fatalf("expected 2 project dirs, got %d: %v", len(dirs), dirs)
	}

	found := make(map[string]bool)
	for _, d := range dirs {
		found[d] = true
	}
	if !found[proj] {
		t.Errorf("expected %s in results", proj)
	}
	if !found[nested] {
		t.Errorf("expected %s in results", nested)
	}
}

func TestScan_ExcludesVenv(t *testing.T) {
	root := t.TempDir()

	// Create a venv with a requirements.txt inside (should be skipped)
	venv := filepath.Join(root, "myenv")
	os.MkdirAll(venv, 0o755)
	os.WriteFile(filepath.Join(venv, "pyvenv.cfg"), []byte("home = /usr/bin"), 0o644)
	os.WriteFile(filepath.Join(venv, "requirements.txt"), []byte("flask"), 0o644)

	// Create a real project
	proj := filepath.Join(root, "myapp")
	os.MkdirAll(proj, 0o755)
	os.WriteFile(filepath.Join(proj, "requirements.txt"), []byte("flask"), 0o644)

	dirs, err := Scan(nil, nil, []string{root})
	if err != nil {
		t.Fatal(err)
	}

	if len(dirs) != 1 {
		t.Fatalf("expected 1 project dir, got %d: %v", len(dirs), dirs)
	}
	if dirs[0] != proj {
		t.Errorf("expected %s, got %s", proj, dirs[0])
	}
}

func TestScan_AutoExcludesToStore(t *testing.T) {
	root := t.TempDir()

	// Create a venv
	venv := filepath.Join(root, "myenv")
	os.MkdirAll(venv, 0o755)
	os.WriteFile(filepath.Join(venv, "pyvenv.cfg"), []byte("home = /usr/bin"), 0o644)

	// Open a store
	dbPath := filepath.Join(root, "excludes.db")
	store, err := classifier.OpenExcludeStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	_, err = Scan(store, nil, []string{root})
	if err != nil {
		t.Fatal(err)
	}

	// The venv's inode should now be in the store
	inode, err := classifier.InodeOf(venv)
	if err != nil {
		t.Fatal(err)
	}
	if !store.IsExcluded(inode) {
		t.Error("venv inode should have been auto-excluded during scan")
	}
}

// TestScanOne_ParityWithScan asserts that ScanOne over a single root
// returns the same project dirs as Scan called with that root, so the
// runtime-discovery path (which calls ScanOne) applies identical
// exclusion rules to the startup path (which calls Scan).
func TestScanOne_ParityWithScan(t *testing.T) {
	root := t.TempDir()

	// Real project
	proj := filepath.Join(root, "alpha")
	os.MkdirAll(proj, 0o755)
	os.WriteFile(filepath.Join(proj, "go.mod"), []byte("module a"), 0o644)

	// Nested project inside a node_modules — should be excluded by
	// the classifier layer regardless of which entry point we use.
	nm := filepath.Join(root, "beta", "node_modules", "lib")
	os.MkdirAll(nm, 0o755)
	os.WriteFile(filepath.Join(nm, "package.json"), []byte("{}"), 0o644)

	// Another real project at a deeper level
	deep := filepath.Join(root, "gamma", "sub", "app")
	os.MkdirAll(deep, 0o755)
	os.WriteFile(filepath.Join(deep, "Cargo.toml"), []byte("[package]\n"), 0o644)

	got1, err := Scan(nil, nil, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	got2, err := ScanOne(nil, nil, root)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got1)
	sort.Strings(got2)
	if len(got1) != len(got2) {
		t.Fatalf("Scan returned %d dirs, ScanOne returned %d (%v vs %v)",
			len(got1), len(got2), got1, got2)
	}
	for i := range got1 {
		if got1[i] != got2[i] {
			t.Errorf("at index %d: Scan=%q ScanOne=%q", i, got1[i], got2[i])
		}
	}
}

// TestScanOne_MissingRoot: a non-existent root path must not error —
// ScanOne is called from the periodic-rescan ticker on every configured
// root, and an ephemerally-missing one (e.g. an unmounted external drive)
// should degrade to an empty slice, not kill the goroutine.
func TestScanOne_MissingRoot(t *testing.T) {
	got, err := ScanOne(nil, nil, filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("ScanOne on missing root returned error %v; expected empty slice", err)
	}
	if len(got) != 0 {
		t.Errorf("missing root should yield empty slice, got %v", got)
	}
}

// TestScan_HonorsExcludesMatcher verifies the user-facing path-based
// exclusion layer: a project living under a matcher-covered subtree is
// skipped by the scan, even though it has a legitimate lockfile and
// would otherwise be returned as a project dir.
func TestScan_HonorsExcludesMatcher(t *testing.T) {
	root := t.TempDir()

	// Monorepo layout: `kept` is a real project, `legacy/pkg-a` has its
	// own lockfile but lives under a subtree the user excluded.
	kept := filepath.Join(root, "kept-project")
	os.MkdirAll(kept, 0o755)
	os.WriteFile(filepath.Join(kept, "package.json"), []byte("{}"), 0o644)

	excludedSub := filepath.Join(root, "legacy", "pkg-a")
	os.MkdirAll(excludedSub, 0o755)
	os.WriteFile(filepath.Join(excludedSub, "package.json"), []byte("{}"), 0o644)

	// Build a matcher with a prefix rule covering the whole `legacy` tree.
	rulesPath := filepath.Join(t.TempDir(), "excludes")
	legacy := filepath.Join(root, "legacy")
	os.WriteFile(rulesPath, []byte(legacy+"\n"), 0o644)
	m, err := excludes.Load(rulesPath)
	if err != nil {
		t.Fatalf("Load matcher: %v", err)
	}

	dirs, err := Scan(nil, m, []string{root})
	if err != nil {
		t.Fatal(err)
	}

	if len(dirs) != 1 {
		t.Fatalf("expected 1 project (excluded subtree dropped), got %d: %v", len(dirs), dirs)
	}
	if dirs[0] != kept {
		t.Errorf("expected %s, got %s", kept, dirs[0])
	}
}
