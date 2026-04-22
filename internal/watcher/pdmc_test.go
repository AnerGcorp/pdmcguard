// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package watcher

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestIsPDMC(t *testing.T) {
	yes := []string{
		"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"pyproject.toml", "requirements.txt", "Pipfile", "Pipfile.lock",
		"Cargo.toml", "Cargo.lock",
		"go.mod", "go.sum",
		"Gemfile", "Gemfile.lock",
		"composer.json", "composer.lock",
	}
	for _, f := range yes {
		if !IsPDMC(f) {
			t.Errorf("IsPDMC(%q) = false, want true", f)
		}
	}

	no := []string{
		"index.js", "README.md", "Package.json", "PACKAGE.JSON",
		"go.mod.bak", "package.jsonl", "Cargo.toml.orig",
		"main.go", ".gitignore", "Dockerfile",
	}
	for _, f := range no {
		if IsPDMC(f) {
			t.Errorf("IsPDMC(%q) = true, want false", f)
		}
	}
}

func TestPDMCFiles_Count(t *testing.T) {
	if got := len(PDMCFiles); got != 16 {
		t.Errorf("PDMCFiles has %d entries, want 16", got)
	}
}

// writeFiles creates the given files (empty body) inside dir. Short-circuit
// helper for the enumeration tests.
func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// eventEcos returns the ecosystems of events, sorted. Used for order-
// insensitive assertions — map iteration order in EnumeratePDMCFiles is
// nondeterministic.
func eventEcos(evs []PDMCChangeEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Ecosystem
	}
	sort.Strings(out)
	return out
}

func TestEnumeratePDMCFiles_Empty(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "README.md", "main.go", ".gitignore")

	evs := EnumeratePDMCFiles([]string{dir})
	if len(evs) != 0 {
		t.Errorf("expected 0 events for junk-only dir, got %d: %+v", len(evs), evs)
	}
}

func TestEnumeratePDMCFiles_SingleEcosystem(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "go.mod")

	evs := EnumeratePDMCFiles([]string{dir})
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Ecosystem != "go" {
		t.Errorf("ecosystem = %q, want %q", evs[0].Ecosystem, "go")
	}
	if evs[0].Dir != dir {
		t.Errorf("Dir = %q, want %q", evs[0].Dir, dir)
	}
	if got, want := evs[0].Path, filepath.Join(dir, "go.mod"); got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

// TestEnumeratePDMCFiles_PrefersLockfile guards the optimization that keeps
// multi-file npm projects from doing the classifier roundtrip twice.
func TestEnumeratePDMCFiles_PrefersLockfile(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "package.json", "package-lock.json")

	evs := EnumeratePDMCFiles([]string{dir})
	if len(evs) != 1 {
		t.Fatalf("expected 1 event (lockfile preferred), got %d", len(evs))
	}
	if got, want := evs[0].Path, filepath.Join(dir, "package-lock.json"); got != want {
		t.Errorf("Path = %q, want %q (lockfile should win over manifest)", got, want)
	}
}

// TestEnumeratePDMCFiles_MultiEcosystem exercises the exact scenario that
// motivated making metaKey ecosystem-aware: a polyglot project with both
// a Node and a Go manifest must emit one event per ecosystem.
func TestEnumeratePDMCFiles_MultiEcosystem(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "package.json", "go.mod")

	evs := EnumeratePDMCFiles([]string{dir})
	if len(evs) != 2 {
		t.Fatalf("expected 2 events for multi-ecosystem dir, got %d", len(evs))
	}
	got := eventEcos(evs)
	want := []string{"go", "npm"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ecosystems = %v, want %v", got, want)
			break
		}
	}
}

// TestEnumeratePDMCFiles_SkipsSymlinks is defensive: a symlinked lockfile
// might point outside the project or into itself. Skip anything that isn't
// a regular file so baseline can't be tricked into classifying arbitrary
// targets.
func TestEnumeratePDMCFiles_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "..external", "package.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "package.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	evs := EnumeratePDMCFiles([]string{dir})
	if len(evs) != 0 {
		t.Errorf("expected symlinked lockfile to be ignored, got %+v", evs)
	}
}

func TestEnumeratePDMCFiles_MultipleDirs(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	writeFiles(t, a, "go.mod")
	writeFiles(t, b, "Cargo.lock")

	evs := EnumeratePDMCFiles([]string{a, b})
	if len(evs) != 2 {
		t.Fatalf("expected 2 events across 2 dirs, got %d", len(evs))
	}
	seen := map[string]string{}
	for _, ev := range evs {
		seen[ev.Dir] = ev.Ecosystem
	}
	if seen[a] != "go" {
		t.Errorf("expected dir %s ecosystem=go, got %q", a, seen[a])
	}
	if seen[b] != "crates.io" {
		t.Errorf("expected dir %s ecosystem=crates.io, got %q", b, seen[b])
	}
}
