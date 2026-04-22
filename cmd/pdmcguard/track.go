// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AnerGcorp/pdmcguard/internal/daemon"
)

// cmdTrack registers a path with the running daemon for immediate
// tracking. Default is $PWD; a positional arg overrides. The path is
// canonicalized client-side (abs + EvalSymlinks + Clean) so the daemon's
// handler receives an absolute path and doesn't have to guess at the
// CLI's cwd (which differs from the daemon's cwd under launchd/systemd).
//
// Exit codes:
//
//	0 — daemon accepted the request (including the "no PDMC files" case)
//	1 — path/arg error (not a directory, doesn't exist, bad flag)
//	2 — daemon is not running (actionable — start it)
func cmdTrack(args []string) {
	var pathArg string
	for _, a := range args {
		switch {
		case a == "-h" || a == "--help":
			fmt.Println("usage: pdmcguard track [path]")
			fmt.Println("  Registers a directory with the running daemon.")
			fmt.Println("  Defaults to the current working directory.")
			return
		case a == "":
			continue
		case pathArg == "":
			pathArg = a
		default:
			fmt.Fprintf(os.Stderr, "pdmcguard track: unexpected arg %q\n", a)
			os.Exit(2)
		}
	}

	if pathArg == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pdmcguard track: cwd: %v\n", err)
			os.Exit(1)
		}
		pathArg = cwd
	}

	abs, err := canonicalizeTrackPath(pathArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard track: %v\n", err)
		os.Exit(1)
	}

	resp, err := daemon.SendRequest(daemon.SocketPath(), daemon.Request{
		Op:   "track",
		Path: abs,
	})
	if err != nil {
		if errors.Is(err, daemon.ErrDaemonNotRunning) {
			fmt.Fprintln(os.Stderr, "pdmcguard track: daemon is not running.")
			fmt.Fprintln(os.Stderr, "  Start it via `pdmcguard install` (one-time), or")
			fmt.Fprintln(os.Stderr, "  run `pdmcguard` in a terminal to foreground it.")
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "pdmcguard track: %v\n", err)
		os.Exit(1)
	}

	if !resp.OK {
		fmt.Fprintf(os.Stderr, "pdmcguard track: %s\n", resp.Error)
		os.Exit(1)
	}
	fmt.Println(resp.Message)
}

// canonicalizeTrackPath resolves rel paths, strips symlinks, and
// confirms the target is a directory. Errors map to exit 1 in cmdTrack.
func canonicalizeTrackPath(raw string) (string, error) {
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %w", raw, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%s: no such directory", abs)
		}
		return "", fmt.Errorf("%s: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s: not a directory", abs)
	}
	// EvalSymlinks matches bootstrap.ScanOne's canonicalization so the
	// same project under a symlinked path doesn't get double-tracked.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return filepath.Clean(abs), nil
}
