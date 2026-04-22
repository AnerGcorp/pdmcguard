// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package bootstrap

import (
	"os"
	"path/filepath"
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
