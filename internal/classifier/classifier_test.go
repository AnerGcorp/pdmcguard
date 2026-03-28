// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package classifier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassify_PythonVenv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyvenv.cfg"), []byte("home = /usr/bin"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Classify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != PythonVenv {
		t.Errorf("got %v, want PythonVenv", c.Kind)
	}
}

func TestClassify_NodeModules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Classify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != NodeModules {
		t.Errorf("got %v, want NodeModules", c.Kind)
	}
}

func TestClassify_GitDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "HEAD"), []byte("ref: refs/heads/main"), 0o644)
	os.WriteFile(filepath.Join(dir, "config"), []byte("[core]"), 0o644)
	os.MkdirAll(filepath.Join(dir, "objects"), 0o755)

	c, err := Classify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != GitDir {
		t.Errorf("got %v, want GitDir", c.Kind)
	}
}

func TestClassify_RustTarget(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".rustc_info.json"), []byte("{}"), 0o644)

	c, err := Classify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != RustTarget {
		t.Errorf("got %v, want RustTarget", c.Kind)
	}
}

func TestClassify_Pycache(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "module.cpython-311.pyc"), []byte{}, 0o644)
	os.WriteFile(filepath.Join(dir, "utils.cpython-311.pyc"), []byte{}, 0o644)

	c, err := Classify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != Pycache {
		t.Errorf("got %v, want Pycache", c.Kind)
	}
}

func TestClassify_GoVendor(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "modules.txt"), []byte("# vendor"), 0o644)

	c, err := Classify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != GoVendor {
		t.Errorf("got %v, want GoVendor", c.Kind)
	}
}

func TestClassify_Unknown(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o644)

	c, err := Classify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != Unknown {
		t.Errorf("got %v, want Unknown", c.Kind)
	}
}

func TestClassify_PycacheWithNonPyc(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "module.pyc"), []byte{}, 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte{}, 0o644)

	c, err := Classify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != Unknown {
		t.Errorf("got %v, want Unknown (mixed files)", c.Kind)
	}
}

func TestClassify_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	c, err := Classify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != Unknown {
		t.Errorf("got %v, want Unknown (empty dir)", c.Kind)
	}
}
