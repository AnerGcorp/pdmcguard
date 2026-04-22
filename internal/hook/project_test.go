// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package hook

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFindProjectDir_GoMod(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module test"), 0o644)

	dir, err := FindProjectDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if dir != root {
		t.Errorf("expected %s, got %s", root, dir)
	}
}

func TestFindProjectDir_PackageJSON(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "package.json"), []byte("{}"), 0o644)

	dir, err := FindProjectDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if dir != root {
		t.Errorf("expected %s, got %s", root, dir)
	}
}

func TestFindProjectDir_WalksUp(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module test"), 0o644)

	sub := filepath.Join(root, "cmd", "app")
	os.MkdirAll(sub, 0o755)

	dir, err := FindProjectDir(sub)
	if err != nil {
		t.Fatal(err)
	}
	if dir != root {
		t.Errorf("expected %s (walked up), got %s", root, dir)
	}
}

func TestFindProjectDir_NestedProject(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module parent"), 0o644)

	inner := filepath.Join(root, "services", "api")
	os.MkdirAll(inner, 0o755)
	os.WriteFile(filepath.Join(inner, "package.json"), []byte("{}"), 0o644)

	// Starting from inner — should find inner, not root
	dir, err := FindProjectDir(inner)
	if err != nil {
		t.Fatal(err)
	}
	if dir != inner {
		t.Errorf("expected inner %s, got %s", inner, dir)
	}
}

func TestFindProjectDir_NoProject(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "README.md"), []byte("hello"), 0o644)

	_, err := FindProjectDir(root)
	if !errors.Is(err, ErrNoProject) {
		t.Errorf("expected ErrNoProject, got %v", err)
	}
}

// TestFindProjectDir_StopsAtHome guards against the "every new terminal
// prints the banner" regression. With a stray package.json in $HOME and a
// subdirectory without any PDMC file, FindProjectDir must report
// ErrNoProject — not bubble up and match $HOME.
func TestFindProjectDir_StopsAtHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Stray lockfile-ish marker directly in $HOME (common real-world accident).
	os.WriteFile(filepath.Join(home, "package.json"), []byte("{}"), 0o644)

	// User's actual cwd — a subdir of $HOME with no PDMC files.
	sub := filepath.Join(home, "projects", "scratch")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := FindProjectDir(sub)
	if !errors.Is(err, ErrNoProject) {
		t.Errorf("expected ErrNoProject (walk should stop at $HOME), got err=%v", err)
	}
}

// TestFindProjectDir_MatchesProjectUnderHome ensures the $HOME bailout
// does not break the common case of a real project beneath $HOME.
func TestFindProjectDir_MatchesProjectUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	proj := filepath.Join(home, "code", "myapp")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(proj, "go.mod"), []byte("module myapp"), 0o644)

	sub := filepath.Join(proj, "internal")
	os.MkdirAll(sub, 0o755)

	dir, err := FindProjectDir(sub)
	if err != nil {
		t.Fatalf("expected to find project under $HOME, got err=%v", err)
	}
	if dir != proj {
		t.Errorf("expected %s, got %s", proj, dir)
	}
}
