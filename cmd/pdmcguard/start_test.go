// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAcquirePidfile_HappyPath covers the first-start case: no pidfile
// on disk, so we write one with our own PID.
func TestAcquirePidfile_HappyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := acquirePidfile(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("pidfile not written: %v", err)
	}
	pid, err := parsePid(string(data))
	if err != nil {
		t.Fatalf("pidfile malformed: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("pidfile has PID %d, want %d", pid, os.Getpid())
	}
}

// TestAcquirePidfile_AlreadyRunning is the duplicate-start guard. A live
// PID in the pidfile must cause acquire to return an error so the second
// daemon doesn't start and double-bind the socket.
func TestAcquirePidfile_AlreadyRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	// Parent shell PID (PPID) is guaranteed-alive while the test runs.
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getppid())), 0o600); err != nil {
		t.Fatal(err)
	}
	err := acquirePidfile(path)
	if err == nil {
		t.Fatal("expected error when live PID present, got nil")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("expected error about already running, got %q", err.Error())
	}
}

// TestAcquirePidfile_StalePidfile — after a crash the pidfile lingers
// but the recorded PID is dead. Acquire must overwrite instead of
// refusing, otherwise the daemon is permanently unable to restart.
func TestAcquirePidfile_StalePidfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	// PID 0 is never a real process; isProcessAlive treats Kill(0,0) as
	// reserved and syscall.Kill rejects it with EINVAL — but parsePid
	// rejects pid<=0, so we use a PID that is syntactically valid but
	// almost certainly not running. PID 999999 is above typical
	// pid_max on macOS/Linux.
	if err := os.WriteFile(path, []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := acquirePidfile(path); err != nil {
		t.Fatalf("expected stale pidfile to be overwritten, got %v", err)
	}
	data, _ := os.ReadFile(path)
	pid, _ := parsePid(string(data))
	if pid != os.Getpid() {
		t.Errorf("stale pidfile was not overwritten; got PID %d, want %d", pid, os.Getpid())
	}
}

// TestAcquirePidfile_MalformedPidfile — a pidfile with garbage (empty,
// truncated write, partial flush) should be treated as recoverable, not
// a hard block. parsePid fails → we overwrite.
func TestAcquirePidfile_MalformedPidfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := os.WriteFile(path, []byte("not-a-pid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := acquirePidfile(path); err != nil {
		t.Fatalf("expected malformed pidfile to be overwritten, got %v", err)
	}
}

// TestParsePid covers the happy path and the defense against negative /
// zero PIDs (which syscall.Kill treats as process-group targets — we
// don't want a garbage pidfile turning into a group signal).
func TestParsePid(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"12345\n", 12345, false},
		{"12345", 12345, false},
		{"  42  ", 42, false},
		{"0\n", 0, true},
		{"-1\n", 0, true},
		{"", 0, true},
		{"abc\n", 0, true},
	}
	for _, c := range cases {
		got, err := parsePid(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parsePid(%q) error = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("parsePid(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestIsProcessAlive sanity checks the POSIX liveness probe on two
// known inputs: our own PID (definitely alive) and PID 999999 (almost
// certainly above pid_max, so ESRCH).
func TestIsProcessAlive(t *testing.T) {
	if !isProcessAlive(os.Getpid()) {
		t.Error("isProcessAlive(self) = false, want true")
	}
	if isProcessAlive(999999) {
		t.Error("isProcessAlive(999999) = true, want false")
	}
}
