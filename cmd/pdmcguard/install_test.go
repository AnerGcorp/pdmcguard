// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyBinary_RejectsEmpty covers the exact failure mode observed on
// the maintainer's machine: `go build -o` silently emitted a 0-byte file,
// install happily copied it, and every `cd` invoked an empty binary.
func TestVerifyBinary_RejectsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o755); err != nil {
		t.Fatal(err)
	}

	err := verifyBinary(path)
	if err == nil {
		t.Fatal("expected error for 0-byte file, got nil")
	}
	if !strings.Contains(err.Error(), "0 bytes") {
		t.Errorf("expected error to mention '0 bytes', got %q", err.Error())
	}
}

// TestVerifyBinary_RejectsNonExec guards the partial-scp / wrong-mode case.
// A readable-but-not-executable source would produce an install that the
// shell hook could never invoke.
func TestVerifyBinary_RejectsNonExec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := verifyBinary(path)
	if err == nil {
		t.Fatal("expected error for non-executable file, got nil")
	}
	if !strings.Contains(err.Error(), "not executable") {
		t.Errorf("expected error to mention 'not executable', got %q", err.Error())
	}
}

func TestVerifyBinary_AcceptsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := verifyBinary(path); err != nil {
		t.Fatalf("expected nil for valid binary, got %v", err)
	}
}

func TestVerifyBinary_RejectsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")

	err := verifyBinary(path)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Errorf("expected error to mention 'stat', got %q", err.Error())
	}
}
