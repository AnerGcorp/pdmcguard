// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AnerGcorp/pdmcguard/internal/bootstrap"
	"github.com/AnerGcorp/pdmcguard/internal/classifier"
	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/watcher"
)

// Set by -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Collect --root flags for custom scan roots (before command parsing)
	var extraRoots []string
	var filteredArgs []string
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--root" && i+1 < len(os.Args) {
			extraRoots = append(extraRoots, os.Args[i+1])
			i++
		} else {
			filteredArgs = append(filteredArgs, os.Args[i])
		}
	}

	if len(filteredArgs) > 0 {
		switch filteredArgs[0] {
		case "version", "--version", "-v":
			fmt.Printf("pdmcguard %s (commit: %s, built: %s)\n", version, commit, date)
			return

		case "status":
			cmdStatus()
			return

		case "install":
			fmt.Println("pdmcguard install — not yet implemented (Step 2.6)")
			os.Exit(1)

		case "uninstall":
			fmt.Println("pdmcguard uninstall — not yet implemented (Step 2.6)")
			os.Exit(1)

		case "pre-check":
			os.Exit(cmdPreCheck())

		case "hook-init":
			cmdHookInit(filteredArgs[1:])
			return

		case "help", "--help", "-h":
			printUsage()
			return

		default:
			fmt.Fprintf(os.Stderr, "pdmcguard: unknown command %q\n", filteredArgs[0])
			printUsage()
			os.Exit(1)
		}
	}

	// Default: run as daemon
	runDaemon(extraRoots)
}

func runDaemon(extraRoots []string) {
	fmt.Printf("pdmcguard %s starting...\n", version)
	fmt.Printf("Config dir: %s\n", config.Dir())

	// Open exclude store
	store, err := classifier.OpenExcludeStore(config.FilePath("excludes.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open exclude store: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	// Bootstrap: scan for project directories
	roots := bootstrap.DefaultRoots()
	roots = append(roots, extraRoots...)
	fmt.Printf("Scanning roots: %v\n", roots)

	dirs, err := bootstrap.Scan(store, roots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: bootstrap scan: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d project directories\n", len(dirs))
	for _, d := range dirs {
		fmt.Printf("  %s\n", d)
	}

	// Start watcher
	w, err := watcher.New(store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create watcher: %v\n", err)
		os.Exit(1)
	}
	defer w.Close()

	for _, d := range dirs {
		added, err := w.Add(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: watch %s: %v\n", d, err)
			continue
		}
		if !added {
			fmt.Printf("  skipped (excluded): %s\n", d)
		}
	}

	fmt.Println("Watching for PDMC file changes... (Ctrl+C to stop)")

	// Handle signals for clean shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case ev := <-w.Events:
			fmt.Printf("[change] %s (%s)\n", ev.Path, ev.Ecosystem)
		case err := <-w.Errors:
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		case <-sig:
			fmt.Println("\nShutting down...")
			return
		}
	}
}

func cmdStatus() {
	fmt.Printf("pdmcguard %s\n", version)
	fmt.Printf("Config dir:  %s\n", config.Dir())
	fmt.Println("Status:      not running (daemon not yet implemented)")
}

func printUsage() {
	fmt.Println(`PDMCGuard — Passive Dependency Monitor & Critical Guard

Usage:
  pdmcguard [--root DIR]    Run as background daemon
  pdmcguard status          Show daemon status and tracked projects
  pdmcguard install         Install daemon, shell hooks, and system service
  pdmcguard uninstall       Remove system service and shell hooks
  pdmcguard pre-check       Check current project for critical advisories (used by shell hook)
  pdmcguard hook-init       Output shell hook snippet (eval "$(pdmcguard hook-init)")
  pdmcguard version         Print version information

Flags:
  --root DIR                Add a custom scan root (repeatable)
  -h, --help                Show this help message
  -v, --version             Print version`)
}
