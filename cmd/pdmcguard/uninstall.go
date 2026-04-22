// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/daemon"
)

func cmdUninstall(args []string) {
	purge := false
	for _, a := range args {
		if a == "--purge" {
			purge = true
		}
	}

	// 1. Stop and remove system service
	svc := daemon.NewServiceManager()
	if svc.IsInstalled() {
		// TODO: svc.Stop() returns before launchd has finished unloading
		// on macOS, so the daemon may briefly still hold the DB handle
		// when we follow up with Uninstall/purge. --purge papers over it
		// (daemon dies on next write into a deleted directory); a proper
		// wait-for-exit is deferred to a later stage.
		_ = svc.Stop()
		if err := svc.Uninstall(); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: service removal failed: %v\n", err)
		} else {
			fmt.Println("  System service removed")
		}
	} else {
		fmt.Println("  No system service found")
	}

	// 2. Remove shell hook
	shell := daemon.DetectShell()
	if err := daemon.RemoveHook(shell); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: shell hook removal failed: %v\n", err)
	} else {
		fmt.Printf("  Shell hook removed from %s\n", daemon.ShellRCPath(shell))
	}

	// 3. Remove the copied binary regardless of --purge. It's an install
	// artifact (put there by cmdInstall), not user data — nothing should
	// invoke it once the service and shell hook are gone. Leaving it
	// behind means a later `pdmcguard install` from a new checkout races
	// against a stale binary, and users who "uninstalled" are surprised
	// to still see the file.
	binDir := filepath.Join(config.Dir(), "bin")
	if err := os.RemoveAll(binDir); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: failed to remove %s: %v\n", binDir, err)
	} else {
		fmt.Printf("  Binary removed: %s\n", binDir)
	}

	// 4. Optionally purge the rest of the config directory (user data:
	// credentials.json, cache.db, queue.db, machine_id, logs).
	if purge {
		dir := config.Dir()
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: failed to remove %s: %v\n", dir, err)
		} else {
			fmt.Printf("  Config directory removed: %s\n", dir)
		}
	} else {
		fmt.Printf("  Config directory kept: %s (use --purge to remove)\n", config.Dir())
	}

	fmt.Println()
	fmt.Println("PDMCGuard uninstalled.")
}
