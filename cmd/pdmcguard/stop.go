// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/daemon"
)

// cmdStop halts the PDMCGuard daemon. Mirrors cmdStart: if a service
// manager is registered, delegates to it; otherwise reads the pidfile
// and escalates SIGTERM → (5s grace) → SIGKILL. Exits 0 in the "already
// stopped" / "stale pidfile" cases so `pdmcguard stop` is idempotent
// and safe to chain after a crash.
//
// Exit codes:
//
//	0 — daemon stopped, or was already stopped
//	1 — stop failed (service error, signal error)
//	2 — bad flag
func cmdStop(args []string) {
	for _, a := range args {
		switch a {
		case "-h", "--help":
			fmt.Println("usage: pdmcguard stop")
			fmt.Println("  Stops the daemon. Uses the installed launchd/systemd unit if")
			fmt.Println("  present; otherwise signals the process recorded in")
			fmt.Println("  ~/.pdmcguard/daemon.pid (SIGTERM, escalating to SIGKILL).")
			return
		case "":
			continue
		default:
			fmt.Fprintf(os.Stderr, "pdmcguard stop: unexpected arg %q\n", a)
			os.Exit(2)
		}
	}

	svc := daemon.NewServiceManager()
	if svc.IsInstalled() {
		if err := svc.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "pdmcguard stop: service stop failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("pdmcguard daemon stopped (via system service)")
		return
	}

	pidfile := config.FilePath("daemon.pid")
	data, err := os.ReadFile(pidfile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("pdmcguard: daemon is not running")
			return
		}
		fmt.Fprintf(os.Stderr, "pdmcguard stop: read pidfile: %v\n", err)
		os.Exit(1)
	}

	pid, err := parsePid(string(data))
	if err != nil {
		// Garbage in pidfile — treat as stale and clean up.
		_ = os.Remove(pidfile)
		fmt.Println("pdmcguard: daemon is not running (removed malformed pidfile)")
		return
	}

	if !isProcessAlive(pid) {
		_ = os.Remove(pidfile)
		fmt.Println("pdmcguard: daemon is not running (removed stale pidfile)")
		return
	}

	if err := stopByPID(pid); err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard stop: %v\n", err)
		os.Exit(1)
	}
	_ = os.Remove(pidfile)
	fmt.Printf("pdmcguard daemon stopped (PID %d)\n", pid)
}

// stopByPID sends SIGTERM, polls for exit up to 5 seconds, then escalates
// to SIGKILL. Mirrors the systemd TimeoutStopSec semantic — give the
// daemon a real shot at clean shutdown (close store/cache, flush queue)
// before pulling the rug out. The 100ms poll interval is cheap and keeps
// the common case (daemon stops in <1s) snappy.
func stopByPID(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("send SIGTERM to PID %d: %w", pid, err)
	}

	const graceTimeout = 5 * time.Second
	const pollInterval = 100 * time.Millisecond
	deadline := time.Now().Add(graceTimeout)

	for time.Now().Before(deadline) {
		if !isProcessAlive(pid) {
			return nil
		}
		time.Sleep(pollInterval)
	}

	fmt.Fprintf(os.Stderr, "pdmcguard stop: PID %d did not exit after %s; sending SIGKILL\n",
		pid, graceTimeout)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return fmt.Errorf("send SIGKILL to PID %d: %w", pid, err)
	}
	return nil
}
