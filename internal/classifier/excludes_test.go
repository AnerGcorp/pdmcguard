// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package classifier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExcludeStore_AddAndCheck(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "excludes.db")
	store, err := OpenExcludeStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if store.IsExcluded(12345) {
		t.Error("inode 12345 should not be excluded before Add")
	}

	if err := store.Add(12345, PythonVenv, "/home/user/myenv"); err != nil {
		t.Fatal(err)
	}

	if !store.IsExcluded(12345) {
		t.Error("inode 12345 should be excluded after Add")
	}
}

func TestExcludeStore_Remove(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "excludes.db")
	store, err := OpenExcludeStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	store.Add(99999, NodeModules, "/home/user/project/node_modules")

	if err := store.Remove(99999); err != nil {
		t.Fatal(err)
	}

	if store.IsExcluded(99999) {
		t.Error("inode should not be excluded after Remove")
	}
}

func TestExcludeStore_InodeSurvivesRename(t *testing.T) {
	// Create a real directory and get its inode
	tmpDir := t.TempDir()
	origDir := filepath.Join(tmpDir, "myenv")
	if err := os.Mkdir(origDir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(origDir, "pyvenv.cfg"), []byte("home = /usr/bin"), 0o644)

	inode, err := InodeOf(origDir)
	if err != nil {
		t.Fatal(err)
	}

	// Store the exclusion
	dbPath := filepath.Join(tmpDir, "excludes.db")
	store, err := OpenExcludeStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	store.Add(inode, PythonVenv, origDir)

	// Rename the directory
	renamedDir := filepath.Join(tmpDir, "renamed_env")
	if err := os.Rename(origDir, renamedDir); err != nil {
		t.Fatal(err)
	}

	// Inode should still match after rename
	newInode, err := InodeOf(renamedDir)
	if err != nil {
		t.Fatal(err)
	}
	if newInode != inode {
		t.Fatalf("inode changed after rename: %d → %d", inode, newInode)
	}

	if !store.IsExcluded(newInode) {
		t.Error("renamed directory should still be excluded (same inode)")
	}
}

func TestExcludeStore_Persistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "excludes.db")

	// Open, add, close
	store1, err := OpenExcludeStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store1.Add(77777, GitDir, "/repo/.git")
	store1.Close()

	// Reopen and check
	store2, err := OpenExcludeStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()

	if !store2.IsExcluded(77777) {
		t.Error("exclusion should persist across close/reopen")
	}
}
