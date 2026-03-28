// PDMCGuard — Passive Dependency Monitor & Critical Guard
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
