// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/AnerGcorp/pdmcguard/internal/cache"
	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/hook"
	"github.com/mattn/go-isatty"
)

const maxAlertsShown = 5

// cmdPreCheck checks the current project for critical advisories.
// Returns 0 if clean, 1 if critical advisories found.
func cmdPreCheck() int {
	cwd, err := os.Getwd()
	if err != nil {
		return 0
	}

	projectDir, err := hook.FindProjectDir(cwd)
	if errors.Is(err, hook.ErrNoProject) {
		return 0 // not in a project — silent
	}
	if err != nil {
		return 0
	}

	dbPath := config.FilePath("cache.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return 0 // cache not yet created — silent
	}

	store, err := cache.Open(dbPath)
	if err != nil {
		return 0
	}
	defer store.Close()

	alerts, err := store.CriticalAlerts(projectDir)
	if err != nil || len(alerts) == 0 {
		return 0
	}

	printWarning(projectDir, alerts)
	return 1
}

func printWarning(projectDir string, alerts []cache.Alert) {
	isTTY := isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())

	yellow := ""
	reset := ""
	bold := ""
	if isTTY {
		yellow = "\033[33m"
		reset = "\033[0m"
		bold = "\033[1m"
	}

	fmt.Fprintf(os.Stderr, "%s%s⚠ pdmcguard: %d critical advisor%s in %s%s\n",
		yellow, bold, len(alerts), plural(len(alerts)), projectDir, reset)

	shown := len(alerts)
	if shown > maxAlertsShown {
		shown = maxAlertsShown
	}
	for _, a := range alerts[:shown] {
		summary := a.Summary
		if summary == "" {
			summary = a.Severity
		}
		fmt.Fprintf(os.Stderr, "  • %s (%s): %s\n", a.PackageName, a.AdvisoryID, summary)
	}
	if len(alerts) > maxAlertsShown {
		fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(alerts)-maxAlertsShown)
	}
	fmt.Fprintf(os.Stderr, "Run 'pdmcguard status' for details.\n")
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
