// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/AnerGcorp/pdmcguard/internal/cache"
	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/hook"
	"github.com/mattn/go-isatty"
)

const maxAlertsShown = 5

// preCheckStore is the subset of cache.Store that precheck.go needs.
// Declaring it as an interface lets tests inject an in-memory fake and
// verify the call order (CriticalAlerts → printWarning → MarkShown)
// without touching SQLite or the filesystem.
type preCheckStore interface {
	CriticalAlerts(projectDir string) ([]cache.Alert, error)
	MarkShown(projectDir string) error
	Close() error
}

// openPreCheckStore is the production path for obtaining the cache.
// Tests replace this function with one returning a fake store.
var openPreCheckStore = func() (preCheckStore, error) {
	dbPath := config.FilePath("cache.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	s, err := cache.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// stderrIsTTY reports whether the warning should be written to stderr.
// Declared as a variable so tests can force the non-TTY branch.
var stderrIsTTY = func() bool {
	fd := os.Stderr.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// cmdPreCheck checks the current project for critical advisories.
// Returns 0 if clean, 1 if critical advisories were shown.
func cmdPreCheck() int {
	return runPreCheck(os.Stderr)
}

func runPreCheck(out io.Writer) int {
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

	store, err := openPreCheckStore()
	if err != nil {
		return 0
	}
	defer store.Close()

	alerts, err := store.CriticalAlerts(projectDir)
	if err != nil || len(alerts) == 0 {
		return 0
	}

	// Gate the entire print on a TTY stderr. Before this, the banner
	// leaked into CI logs, piped output, and any non-interactive shell
	// that happened to source .zshrc.
	if !stderrIsTTY() {
		return 0
	}

	printWarning(out, projectDir, alerts)

	// Start the 24h quiet window. Failure to mark is non-fatal — worst
	// case the banner reprints on the next directory change, which is
	// still better than the pre-fix every-prompt spam.
	_ = store.MarkShown(projectDir)
	return 1
}

func printWarning(out io.Writer, projectDir string, alerts []cache.Alert) {
	const (
		yellow = "\033[33m"
		reset  = "\033[0m"
		bold   = "\033[1m"
	)

	fmt.Fprintf(out, "%s%s⚠ pdmcguard: %d critical advisor%s in %s%s\n",
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
		fmt.Fprintf(out, "  • %s (%s): %s\n", a.PackageName, a.AdvisoryID, summary)
	}
	if len(alerts) > maxAlertsShown {
		fmt.Fprintf(out, "  ... and %d more\n", len(alerts)-maxAlertsShown)
	}
	fmt.Fprintf(out, "Run 'pdmcguard status' for details.\n")
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
