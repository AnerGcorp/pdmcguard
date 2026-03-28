// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/AnerGcorp/pdmcguard/internal/config"
)

// Set by -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
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
			fmt.Println("pdmcguard pre-check — not yet implemented (Step 2.3)")
			os.Exit(1)

		case "hook-notify":
			fmt.Println("pdmcguard hook-notify — not yet implemented (Step 2.3)")
			os.Exit(1)

		case "help", "--help", "-h":
			printUsage()
			return

		default:
			fmt.Fprintf(os.Stderr, "pdmcguard: unknown command %q\n", os.Args[1])
			printUsage()
			os.Exit(1)
		}
	}

	// Default: run as daemon
	fmt.Println("pdmcguard daemon — not yet implemented (Step 2.2+)")
	fmt.Printf("Config dir: %s\n", config.Dir())
	os.Exit(1)
}

func cmdStatus() {
	fmt.Printf("pdmcguard %s\n", version)
	fmt.Printf("Config dir:  %s\n", config.Dir())
	fmt.Println("Status:      not running (daemon not yet implemented)")
}

func printUsage() {
	fmt.Println(`PDMCGuard — Passive Dependency Monitor & Critical Guard

Usage:
  pdmcguard                 Run as background daemon
  pdmcguard status          Show daemon status and tracked projects
  pdmcguard install         Install daemon, shell hooks, and system service
  pdmcguard uninstall       Remove system service and shell hooks
  pdmcguard pre-check       Check current project for critical advisories (used by shell hook)
  pdmcguard hook-notify     Notify daemon of PDMC file change (used by shell hook)
  pdmcguard version         Print version information

Flags:
  -h, --help                Show this help message
  -v, --version             Print version`)
}
