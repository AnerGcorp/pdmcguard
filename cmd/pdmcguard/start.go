// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/daemon"
)

// cmdStart activates the PDMCGuard daemon. It refuses to start when a
// daemon is already accepting IPC (uniform liveness signal across service
// and bare paths), then delegates to the installed service manager if
// one is registered, falling back to a background-spawn with Setsid +
// pidfile + log redirect when the user has not run `pdmcguard install`.
//
// Exit codes:
//
//	0 — daemon started (or was started by launchctl/systemctl)
//	1 — daemon already running, or start failed
//	2 — bad flag
func cmdStart(args []string) {
	for _, a := range args {
		switch a {
		case "-h", "--help":
			fmt.Println("usage: pdmcguard start")
			fmt.Println("  Starts the daemon. Uses the installed launchd/systemd unit if")
			fmt.Println("  present; otherwise spawns a detached background process with")
			fmt.Println("  logs at ~/.pdmcguard/daemon.log.")
			return
		case "":
			continue
		default:
			fmt.Fprintf(os.Stderr, "pdmcguard start: unexpected arg %q\n", a)
			os.Exit(2)
		}
	}

	// Liveness pre-check: an accepting socket means something is already
	// running, regardless of whether it was spawned via launchctl, a
	// prior `pdmcguard start`, or a bare foreground `pdmcguard`.
	if conn, err := daemon.Dial(daemon.SocketPath()); err == nil {
		conn.Close()
		fmt.Fprintln(os.Stderr, "pdmcguard start: daemon is already running")
		fmt.Fprintln(os.Stderr, "  Run `pdmcguard status` to inspect it, or `pdmcguard stop` to halt.")
		os.Exit(1)
	}

	svc := daemon.NewServiceManager()
	if svc.IsInstalled() {
		if err := svc.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "pdmcguard start: service start failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("pdmcguard daemon started (via system service)")
		fmt.Printf("  Logs: %s\n", config.FilePath("daemon.log"))
		return
	}

	pid, err := spawnDetachedDaemon()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard start: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("pdmcguard daemon started (PID %d)\n", pid)
	fmt.Printf("  Logs: %s\n", config.FilePath("daemon.log"))
	fmt.Println("  Install the system service with `pdmcguard install` for")
	fmt.Println("  auto-start on login and crash-restart supervision.")
}

// spawnDetachedDaemon re-execs the current binary with a new session
// (Setsid), redirects stdio to /dev/null + daemon.log, and returns the
// child PID. The child enters the default code path (runDaemon) and
// writes its own pidfile via acquirePidfile.
//
// We don't pass any sentinel env/flag: runDaemon is already the default
// branch of main, so the child falls into it naturally. Keeping the
// invocation flag-free means a human reading `ps` sees the same command
// line they'd see for a foreground daemon.
func spawnDetachedDaemon() (int, error) {
	logPath := config.FilePath("daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("open log %s: %w", logPath, err)
	}
	// logFile is inherited by the child; it's safe (and cheap) to close
	// our own descriptor after cmd.Start returns — the child keeps its
	// inherited fd. Not closing would leak one fd per start in long-
	// lived parents, but this parent exits immediately so it's moot.
	defer logFile.Close()

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	self, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve self: %w", err)
	}

	cmd := exec.Command(self)
	cmd.Stdin = devNull
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Setsid detaches from the controlling terminal so a shell
	// close/SIGHUP won't propagate. Setpgid would also work for SIGHUP
	// isolation but Setsid is the stronger guarantee (new session leader).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("spawn: %w", err)
	}
	// Detach: we don't cmd.Wait() — the child runs independently and
	// its reaping is handled by init(1) once we exit.
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	return pid, nil
}

// acquirePidfile writes this process's PID to path, tolerating a stale
// file from a prior crash. Returns an error iff another live PID is
// already recorded. Called by runDaemon so all start paths (service,
// background-spawn, foreground) converge on a single authority.
//
// The check uses `kill -0` semantics: a signal of 0 is a permission +
// existence probe. ESRCH = no such process (stale); nil = alive; EPERM
// = alive but owned by someone else (treat as alive out of caution —
// we shouldn't overwrite their pidfile even if we technically could).
func acquirePidfile(path string) error {
	if data, err := os.ReadFile(path); err == nil {
		if pid, perr := parsePid(string(data)); perr == nil {
			if isProcessAlive(pid) {
				return fmt.Errorf("daemon already running (PID %d); remove %s if you're sure it isn't",
					pid, path)
			}
			// Stale file: PID is dead. Fall through to overwrite.
		}
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600)
}

// parsePid tolerates a trailing newline (the format we write) or any
// stray whitespace another process might have left behind.
func parsePid(raw string) (int, error) {
	var pid int
	_, err := fmt.Sscanf(raw, "%d", &pid)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("not a PID: %q", raw)
	}
	return pid, nil
}

// isProcessAlive reports whether pid refers to a running process this
// user can see. Signal 0 is the POSIX liveness probe. EPERM (process
// exists but is owned by someone else) is treated as alive — declining
// to stomp on another user's pidfile is the safe default even though
// ~/.pdmcguard is a single-user directory.
func isProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}
