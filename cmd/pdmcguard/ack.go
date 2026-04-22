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
	"github.com/AnerGcorp/pdmcguard/internal/sync"
)

// cmdAck records a permanent dismissal of an advisory.
//
// Usage:
//
//	pdmcguard ack <advisory-id>                  # scope = current project
//	pdmcguard ack <advisory-id> --all-projects   # scope = global ("*")
//	pdmcguard ack --list                         # print all ack rows
func cmdAck(args []string) { ackOrUnack(args, "ack") }

// cmdUnack reverses a prior ack. Accepts the same --all-projects flag so
// users can undo a global ack without guessing the scope encoding.
func cmdUnack(args []string) { ackOrUnack(args, "unack") }

// ackOrUnack parses args manually (no flag library — matches install.go /
// login.go), resolves the scope, and dispatches to Ack / Unack / ListAcks.
// verb must be "ack" or "unack"; --list is only valid under "ack".
func ackOrUnack(args []string, verb string) {
	var id string
	var global, list bool
	for _, a := range args {
		switch {
		case a == "--all-projects":
			global = true
		case a == "--list" && verb == "ack":
			list = true
		case id == "" && a != "":
			id = a
		default:
			fmt.Fprintf(os.Stderr, "pdmcguard %s: unexpected arg %q\n", verb, a)
			os.Exit(2)
		}
	}

	store, err := openAckStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard %s: %v\n", verb, err)
		os.Exit(1)
	}
	defer store.Close()

	if list {
		runListAcks(store)
		return
	}

	if id == "" {
		fmt.Fprintf(os.Stderr, "pdmcguard %s: missing advisory id\n", verb)
		fmt.Fprintf(os.Stderr, "usage: pdmcguard %s <advisory-id> [--all-projects]\n", verb)
		os.Exit(2)
	}

	scope, label, err := resolveAckScope(global)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard %s: %v\n", verb, err)
		os.Exit(1)
	}

	switch verb {
	case "ack":
		runAck(store, scope, label, id)
	case "unack":
		runUnack(store, scope, label, id)
	}
}

// openAckStore is a var so tests can swap it. Mirrors precheck.go's pattern.
var openAckStore = func() (*cache.Store, error) {
	dbPath := config.FilePath("cache.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("no cache at %s — run the daemon once first", dbPath)
	}
	return cache.Open(dbPath)
}

// resolveAckScope returns the project_dir value to store in project_acks
// plus a human-readable label for the confirmation message. For global
// acks, it returns the "*" sentinel. For per-project acks, it walks up
// from cwd via hook.FindProjectDir — same canonicalization as the banner,
// so acking from /tmp/foo/sub matches the /tmp/foo scope the banner
// showed.
func resolveAckScope(global bool) (scope, label string, err error) {
	if global {
		return cache.GlobalAckScope, "all projects", nil
	}
	cwd, werr := os.Getwd()
	if werr != nil {
		return "", "", fmt.Errorf("resolve cwd: %w", werr)
	}
	projectDir, perr := hook.FindProjectDir(cwd)
	if errors.Is(perr, hook.ErrNoProject) {
		return "", "", fmt.Errorf(
			"not inside a known project directory (cwd=%s) — cd into a project or pass --all-projects",
			cwd,
		)
	}
	if perr != nil {
		return "", "", fmt.Errorf("find project dir: %w", perr)
	}
	return projectDir, projectDir, nil
}

func runAck(store *cache.Store, scope, label, id string) {
	// Typo heuristic: warn (don't refuse) if the advisory isn't currently
	// on any project. Prophylactic acks are legitimate — a user might want
	// to silence something before it lands.
	active, err := store.AdvisoryIsActive(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard ack: check advisory: %v\n", err)
		os.Exit(1)
	}
	if !active {
		fmt.Fprintf(os.Stderr,
			"warn: advisory %q is not currently active on any project — ack recorded anyway\n",
			id,
		)
	}

	if err := store.Ack(scope, id); err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard ack: %v\n", err)
		os.Exit(1)
	}

	// Reconcile the sentinel so a fully-acked machine silences the shell
	// hook without waiting for the next daemon sync.
	sync.ReconcileAlertSentinel(store)

	fmt.Printf("Acked %s in %s\n", id, label)
}

func runUnack(store *cache.Store, scope, label, id string) {
	if err := store.Unack(scope, id); err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard unack: %v\n", err)
		os.Exit(1)
	}
	// Sentinel may need to flip back on if this was the last suppressor
	// and critical alerts are now visible again.
	sync.ReconcileAlertSentinel(store)
	fmt.Printf("Unacked %s in %s\n", id, label)
}

func runListAcks(store *cache.Store) {
	acks, err := store.ListAcks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard ack: list: %v\n", err)
		os.Exit(1)
	}
	if len(acks) == 0 {
		fmt.Println("No acks recorded.")
		return
	}
	fmt.Printf("%-6s  %-40s  %s\n", "SCOPE", "ADVISORY", "ACKED")
	for _, a := range acks {
		scope := a.ProjectDir
		if scope == cache.GlobalAckScope {
			scope = "global"
		}
		fmt.Printf("%-6s  %-40s  %s\n", scope, a.AdvisoryID, a.AckedAt.Format("2006-01-02 15:04"))
	}
}
