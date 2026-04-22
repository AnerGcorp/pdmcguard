// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

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

	// 3. Optionally purge config directory
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
