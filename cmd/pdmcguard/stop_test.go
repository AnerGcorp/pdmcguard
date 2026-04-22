// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package main

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// reapChild starts a goroutine that Waits on cmd and closes the
// returned channel once the child is reaped. Using close-based
// signaling (not a value send) lets multiple readers — the test body
// and t.Cleanup — synchronize on the same event without racing to
// consume a channel value.
//
// Matters here because in production stopByPID lives in a separate
// process from the daemon; a zombie is impossible. In-test we share a
// process tree with the subject, so we must reap concurrently for
// isProcessAlive (kill -0) to observe the death.
func reapChild(cmd *exec.Cmd) (done chan struct{}, waitErr *error) {
	done = make(chan struct{})
	var err error
	go func() {
		err = cmd.Wait()
		close(done)
	}()
	return done, &err
}

// TestStopByPID_KillsLiveProcess spawns `sleep 9999` and verifies
// stopByPID drops it via SIGTERM without escalating to SIGKILL (sleep
// handles SIGTERM immediately).
func TestStopByPID_KillsLiveProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess")
	}

	cmd := exec.Command("sleep", "9999")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	pid := cmd.Process.Pid
	reaped, _ := reapChild(cmd)
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		<-reaped
	})

	if !isProcessAlive(pid) {
		t.Fatalf("subject PID %d not alive before stop", pid)
	}

	start := time.Now()
	if err := stopByPID(pid); err != nil {
		t.Fatalf("stopByPID: %v", err)
	}
	elapsed := time.Since(start)

	select {
	case <-reaped:
	case <-time.After(time.Second):
		t.Fatal("child did not exit after stopByPID returned")
	}

	if elapsed > 3*time.Second {
		t.Errorf("stopByPID took %s; SIGTERM path should be fast", elapsed)
	}
}

// TestStopByPID_SendsSIGTERMFirst verifies stopByPID escalates rather
// than opening with SIGKILL. A bash trap captures SIGTERM and exits 0;
// if stopByPID had sent SIGKILL up front, the trap would be bypassed
// and Wait() would report a non-zero signal status.
func TestStopByPID_SendsSIGTERMFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess")
	}

	cmd := exec.Command("sh", "-c", `trap 'exit 0' TERM; sleep 9999 & wait`)
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn trap: %v", err)
	}
	pid := cmd.Process.Pid
	reaped, waitErr := reapChild(cmd)
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		<-reaped
	})

	// Give sh a moment to install the trap before we signal it.
	time.Sleep(200 * time.Millisecond)

	if err := stopByPID(pid); err != nil {
		t.Fatalf("stopByPID: %v", err)
	}

	select {
	case <-reaped:
	case <-time.After(2 * time.Second):
		t.Fatal("child did not exit after stopByPID returned")
	}
	if *waitErr != nil {
		t.Fatalf("child exited non-zero (%v); trap should have caught SIGTERM and exited 0", *waitErr)
	}
}
