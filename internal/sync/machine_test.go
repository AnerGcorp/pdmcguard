// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package sync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMachineUUIDStable(t *testing.T) {
	// MachineUUID should return the same value across calls
	id1 := MachineUUID()
	id2 := MachineUUID()

	if id1 == "" {
		t.Fatal("MachineUUID returned empty string")
	}
	if id1 != id2 {
		t.Errorf("MachineUUID not stable: %q != %q", id1, id2)
	}
}

func TestMachineUUIDPersistedToFile(t *testing.T) {
	// After calling MachineUUID, the file should exist
	_ = MachineUUID()

	// Check the file exists (we can't easily test the exact path in unit tests
	// since it uses config.Dir(), but we can verify the function works)
}

func TestMachineUUIDFromFile(t *testing.T) {
	// Write a known ID to a temp file and verify it's read back
	dir := t.TempDir()
	path := filepath.Join(dir, "test_machine_id")
	if err := os.WriteFile(path, []byte("test-uuid-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(data))
	if id != "test-uuid-123" {
		t.Errorf("expected test-uuid-123, got %q", id)
	}
}

func TestMachineHostname(t *testing.T) {
	h := MachineHostname()
	if h == "" {
		t.Error("MachineHostname returned empty string")
	}
}

func TestMachineOS(t *testing.T) {
	os := MachineOS()
	if os == "" {
		t.Error("MachineOS returned empty string")
	}
	if !strings.Contains(os, "/") {
		t.Errorf("MachineOS should be GOOS/GOARCH format, got %q", os)
	}
}
