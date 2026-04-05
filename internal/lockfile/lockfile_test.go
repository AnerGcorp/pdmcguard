// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func testdataPath(name string) string {
	return filepath.Join("testdata", name)
}

// sortPkgs sorts packages by name for deterministic comparison.
func sortPkgs(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name < pkgs[j].Name
	})
}

func findPkg(pkgs []Package, name string) (Package, bool) {
	for _, p := range pkgs {
		if p.Name == name {
			return p, true
		}
	}
	return Package{}, false
}

// ── go.sum ──────────────────────────────────────────────────────────────────

func TestParseGoSum(t *testing.T) {
	pkgs, err := parseGoSum(testdataPath("go.sum"))
	if err != nil {
		t.Fatal(err)
	}

	// 3 unique modules (each has h1 + go.mod line = 6 lines, but deduplicated)
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	p, ok := findPkg(pkgs, "github.com/fsnotify/fsnotify")
	if !ok {
		t.Fatal("fsnotify not found")
	}
	if p.Version != "v1.9.0" {
		t.Errorf("fsnotify version = %q, want v1.9.0", p.Version)
	}
}

func TestParseGoSumDeduplicates(t *testing.T) {
	pkgs, err := parseGoSum(testdataPath("go.sum"))
	if err != nil {
		t.Fatal(err)
	}

	// Count occurrences of fsnotify
	count := 0
	for _, p := range pkgs {
		if p.Name == "github.com/fsnotify/fsnotify" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("fsnotify appears %d times, want 1", count)
	}
}

// ── package-lock.json ───────────────────────────────────────────────────────

func TestParsePackageLockV3(t *testing.T) {
	pkgs, err := parsePackageLock(testdataPath("package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	p, ok := findPkg(pkgs, "lodash")
	if !ok {
		t.Fatal("lodash not found")
	}
	if p.Version != "4.17.21" {
		t.Errorf("lodash version = %q, want 4.17.21", p.Version)
	}

	// Scoped package
	p, ok = findPkg(pkgs, "@babel/core")
	if !ok {
		t.Fatal("@babel/core not found")
	}
	if p.Version != "7.24.0" {
		t.Errorf("@babel/core version = %q, want 7.24.0", p.Version)
	}
}

func TestParsePackageLockV1(t *testing.T) {
	pkgs, err := parsePackageLock(testdataPath("package-lock-v1.json"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}

	p, ok := findPkg(pkgs, "express")
	if !ok {
		t.Fatal("express not found")
	}
	if p.Version != "4.18.2" {
		t.Errorf("express version = %q, want 4.18.2", p.Version)
	}
}

// ── requirements.txt ────────────────────────────────────────────────────────

func TestParseRequirements(t *testing.T) {
	pkgs, err := parseRequirements(testdataPath("requirements.txt"))
	if err != nil {
		t.Fatal(err)
	}

	// requests, flask, numpy, django = 4 pinned packages
	if len(pkgs) != 4 {
		t.Fatalf("expected 4 packages, got %d: %v", len(pkgs), pkgs)
	}

	p, ok := findPkg(pkgs, "flask")
	if !ok {
		t.Fatal("flask not found")
	}
	if p.Version != "3.0.0" {
		t.Errorf("flask version = %q, want 3.0.0", p.Version)
	}

	// django should have inline comment stripped
	p, ok = findPkg(pkgs, "django")
	if !ok {
		t.Fatal("django not found")
	}
	if p.Version != "5.0.1" {
		t.Errorf("django version = %q, want 5.0.1", p.Version)
	}
}

// ── Cargo.lock ──────────────────────────────────────────────────────────────

func TestParseCargoLock(t *testing.T) {
	pkgs, err := parseCargoLock(testdataPath("Cargo.lock"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	p, ok := findPkg(pkgs, "serde")
	if !ok {
		t.Fatal("serde not found")
	}
	if p.Version != "1.0.197" {
		t.Errorf("serde version = %q, want 1.0.197", p.Version)
	}

	p, ok = findPkg(pkgs, "rand")
	if !ok {
		t.Fatal("rand not found")
	}
	if p.Version != "0.8.5" {
		t.Errorf("rand version = %q, want 0.8.5", p.Version)
	}
}

// ── Gemfile.lock ────────────────────────────────────────────────────────────

func TestParseGemfileLock(t *testing.T) {
	pkgs, err := parseGemfileLock(testdataPath("Gemfile.lock"))
	if err != nil {
		t.Fatal(err)
	}

	// actioncable, actionpack, rails = 3 top-level gems
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d: %v", len(pkgs), pkgs)
	}

	p, ok := findPkg(pkgs, "rails")
	if !ok {
		t.Fatal("rails not found")
	}
	if p.Version != "7.1.3" {
		t.Errorf("rails version = %q, want 7.1.3", p.Version)
	}
}

// ── composer.lock ───────────────────────────────────────────────────────────

func TestParseComposerLock(t *testing.T) {
	pkgs, err := parseComposerLock(testdataPath("composer.lock"))
	if err != nil {
		t.Fatal(err)
	}

	// 2 packages + 1 dev package = 3
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	p, ok := findPkg(pkgs, "laravel/framework")
	if !ok {
		t.Fatal("laravel/framework not found")
	}
	// "v" prefix should be stripped
	if p.Version != "11.0.0" {
		t.Errorf("laravel/framework version = %q, want 11.0.0", p.Version)
	}

	// Dev dependency included
	_, ok = findPkg(pkgs, "phpunit/phpunit")
	if !ok {
		t.Fatal("phpunit/phpunit not found (dev dependency)")
	}
}

// ── Pipfile.lock ────────────────────────────────────────────────────────────

func TestParsePipfileLock(t *testing.T) {
	pkgs, err := parsePipfileLock(testdataPath("Pipfile.lock"))
	if err != nil {
		t.Fatal(err)
	}

	// 2 default + 1 develop = 3
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}

	p, ok := findPkg(pkgs, "requests")
	if !ok {
		t.Fatal("requests not found")
	}
	// "==" prefix should be stripped
	if p.Version != "2.31.0" {
		t.Errorf("requests version = %q, want 2.31.0", p.Version)
	}
}

// ── yarn.lock ───────────────────────────────────────────────────────────────

func TestParseYarnLock(t *testing.T) {
	pkgs, err := parseYarnLock(testdataPath("yarn.lock"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d: %v", len(pkgs), pkgs)
	}

	p, ok := findPkg(pkgs, "@babel/core")
	if !ok {
		t.Fatal("@babel/core not found")
	}
	if p.Version != "7.24.0" {
		t.Errorf("@babel/core version = %q, want 7.24.0", p.Version)
	}

	p, ok = findPkg(pkgs, "lodash")
	if !ok {
		t.Fatal("lodash not found")
	}
	if p.Version != "4.17.21" {
		t.Errorf("lodash version = %q, want 4.17.21", p.Version)
	}
}

// ── pnpm-lock.yaml ─────────────────────────────────────────────────────────

func TestParsePnpmLock(t *testing.T) {
	pkgs, err := parsePnpmLock(testdataPath("pnpm-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d: %v", len(pkgs), pkgs)
	}

	p, ok := findPkg(pkgs, "lodash")
	if !ok {
		t.Fatal("lodash not found")
	}
	if p.Version != "4.17.21" {
		t.Errorf("lodash version = %q, want 4.17.21", p.Version)
	}

	p, ok = findPkg(pkgs, "@babel/core")
	if !ok {
		t.Fatal("@babel/core not found")
	}
	if p.Version != "7.24.0" {
		t.Errorf("@babel/core version = %q, want 7.24.0", p.Version)
	}
}

// ── Parse dispatcher ────────────────────────────────────────────────────────

func TestParseDispatcher(t *testing.T) {
	// go.sum directly
	pkgs, err := Parse(testdataPath("go.sum"), "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 3 {
		t.Errorf("go.sum: expected 3, got %d", len(pkgs))
	}
}

func TestParseManifestRedirectsToLockFile(t *testing.T) {
	// Create a temp dir with go.mod and go.sum
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	goSum := `github.com/example/pkg v1.0.0 h1:abc=
github.com/example/pkg v1.0.0/go.mod h1:def=
`
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o644); err != nil {
		t.Fatal(err)
	}

	// Parse go.mod should redirect to go.sum
	pkgs, err := Parse(filepath.Join(dir, "go.mod"), "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Errorf("expected 1 package from go.sum via go.mod redirect, got %d", len(pkgs))
	}
}

func TestParseNonexistentLockFile(t *testing.T) {
	// Parse a manifest whose lock file doesn't exist
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// go.sum doesn't exist → nil, nil
	pkgs, err := Parse(filepath.Join(dir, "go.mod"), "go")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if pkgs != nil {
		t.Errorf("expected nil packages, got %v", pkgs)
	}
}

// ── ParseSemver ─────────────────────────────────────────────────────────────

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input string
		want  SemVer
	}{
		{"1.2.3", SemVer{1, 2, 3}},
		{"v1.2.3", SemVer{1, 2, 3}},
		{"1.2.3-rc.1", SemVer{1, 2, 3}},
		{"1.2.3+build", SemVer{1, 2, 3}},
		{"1.2", SemVer{1, 2, 0}},
		{"1", SemVer{1, 0, 0}},
		{"0.0.0", SemVer{0, 0, 0}},
	}

	for _, tt := range tests {
		got := ParseSemver(tt.input)
		if got != tt.want {
			t.Errorf("ParseSemver(%q) = %+v, want %+v", tt.input, got, tt.want)
		}
	}
}

// ── Edge cases ──────────────────────────────────────────────────────────────

func TestParseEmptyFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(empty, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := parseGoSum(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages from empty go.sum, got %d", len(pkgs))
	}
}
