// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package sync

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLockPathLockFile(t *testing.T) {
	dir := t.TempDir()
	goSum := filepath.Join(dir, "go.sum")
	os.WriteFile(goSum, []byte("test"), 0o644)

	got := resolveLockPath(goSum, "go")
	if got != goSum {
		t.Errorf("expected %q, got %q", goSum, got)
	}
}

func TestResolveLockPathManifestRedirect(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")
	goSum := filepath.Join(dir, "go.sum")
	os.WriteFile(goMod, []byte("module test"), 0o644)
	os.WriteFile(goSum, []byte("test"), 0o644)

	got := resolveLockPath(goMod, "go")
	if got != goSum {
		t.Errorf("expected %q, got %q", goSum, got)
	}
}

func TestResolveLockPathNoLockFile(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")
	os.WriteFile(goMod, []byte("module test"), 0o644)

	got := resolveLockPath(goMod, "go")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestResolveLockPathNpmFallbackYarn(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := filepath.Join(dir, "package.json")
	yarnLock := filepath.Join(dir, "yarn.lock")
	os.WriteFile(pkgJSON, []byte("{}"), 0o644)
	os.WriteFile(yarnLock, []byte("test"), 0o644)

	got := resolveLockPath(pkgJSON, "npm")
	if got != yarnLock {
		t.Errorf("expected %q (yarn fallback), got %q", yarnLock, got)
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("hello world"), 0o644)

	h1, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == "" {
		t.Fatal("hash is empty")
	}

	// Same content = same hash
	h2, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("same content should produce same hash")
	}

	// Different content = different hash
	os.WriteFile(path, []byte("hello world!"), 0o644)
	h3, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Error("different content should produce different hash")
	}
}

func TestHashString(t *testing.T) {
	h := hashString("/home/user/project")
	if h == "" {
		t.Fatal("hash is empty")
	}
	if len(h) != 64 { // SHA-256 hex
		t.Errorf("expected 64 char hex, got %d chars", len(h))
	}
}

func TestContentHashDedup(t *testing.T) {
	// Test that hashFile returns the same hash for identical content
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.txt")
	f2 := filepath.Join(dir, "b.txt")
	content := []byte("same content")
	os.WriteFile(f1, content, 0o644)
	os.WriteFile(f2, content, 0o644)

	h1, _ := hashFile(f1)
	h2, _ := hashFile(f2)
	if h1 != h2 {
		t.Error("identical content should produce identical hashes")
	}
}
