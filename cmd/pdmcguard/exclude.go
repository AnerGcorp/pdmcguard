// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AnerGcorp/pdmcguard/internal/cache"
	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/excludes"
	"github.com/AnerGcorp/pdmcguard/internal/sync"
)

// cmdExclude adds a path-based user exclusion rule.
//
// Usage:
//
//	pdmcguard exclude <path>     # absolute path → prefix rule covering subtree
//	pdmcguard exclude <name>     # bare name → basename token matching anywhere
//	pdmcguard exclude --list     # print active user rules + built-in defaults
func cmdExclude(args []string) { excludeOrUnexclude(args, "exclude") }

// cmdUnexclude removes a previously-added rule. Accepts exactly one path
// or basename; the value must match a user rule verbatim (defaults can't
// be removed).
func cmdUnexclude(args []string) { excludeOrUnexclude(args, "unexclude") }

// excludeOrUnexclude is the shared arg-parser + dispatcher, mirroring
// ack.go's ackOrUnack. Manual arg parsing (no flag lib) matches the
// rest of the CLI.
func excludeOrUnexclude(args []string, verb string) {
	var rule string
	var list bool
	for _, a := range args {
		switch {
		case a == "":
			// Skip empty positional args (e.g. `pdmcguard exclude ""`)
			// so the missing-argument check below fires with a helpful
			// message instead of an "unexpected arg \"\"" dead end.
			continue
		case a == "--list" && verb == "exclude":
			list = true
		case rule == "":
			rule = a
		default:
			fmt.Fprintf(os.Stderr, "pdmcguard %s: unexpected arg %q\n", verb, a)
			os.Exit(2)
		}
	}

	matcher, err := openMatcher()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard %s: %v\n", verb, err)
		os.Exit(1)
	}

	if list {
		runListExcludes(matcher)
		return
	}

	if rule == "" {
		fmt.Fprintf(os.Stderr, "pdmcguard %s: missing argument\n", verb)
		fmt.Fprintf(os.Stderr, "usage: pdmcguard %s <path-or-basename>\n", verb)
		os.Exit(2)
	}

	normalized, nerr := normalizeRule(rule)
	if nerr != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard %s: %v\n", verb, nerr)
		os.Exit(2)
	}

	switch verb {
	case "exclude":
		runExclude(matcher, normalized)
	case "unexclude":
		runUnexclude(matcher, normalized)
	}
}

// openMatcher is a var so tests can swap the rules file location without
// fiddling with $HOME. Mirrors openAckStore in ack.go.
var openMatcher = func() (*excludes.Matcher, error) {
	return excludes.Load(config.FilePath("excludes"))
}

// openExcludeCacheStore opens the cache DB for the exclude CLI's DB
// cleanup pass. Separate var so tests can stub it to a temp DB.
var openExcludeCacheStore = func() (*cache.Store, error) {
	dbPath := config.FilePath("cache.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, nil // no cache yet — nothing to clean, that's fine
	}
	return cache.Open(dbPath)
}

// normalizeRule resolves the user's input to its on-disk form.
//
// Accepted shapes:
//   - basename token (no slashes, no tilde): "node_modules" → passthrough.
//   - absolute path: "/a/b" → cleaned, symlinks best-effort resolved.
//   - tilde-home: "~/a/b" → $HOME-expanded, then as absolute.
//   - explicit relative: "./a/b" or "../a/b" → cwd-joined, then absolute.
//
// Rejected: bare slash-containing inputs like "fixtures/legacy". They're
// ambiguous between "relative path the user wanted resolved" and "pattern
// the user wanted treated like a basename" — the matcher's basename rule
// can't accept them, so accepting them at the CLI layer would silently
// produce a cwd-anchored rule that doesn't match what the user typed on
// --list. Better to reject and let them add `./` if they meant cwd.
func normalizeRule(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty rule")
	}

	hasSlash := strings.Contains(raw, string(filepath.Separator))

	// Basename token — punt unchanged. Matcher.Add will validate.
	if !hasSlash && !strings.HasPrefix(raw, "~") {
		return raw, nil
	}

	// Tilde expansion
	if strings.HasPrefix(raw, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home: %w", err)
		}
		raw = filepath.Join(home, raw[2:])
	} else if raw == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home: %w", err)
		}
		raw = home
	}

	if !filepath.IsAbs(raw) {
		// Only explicit relative prefixes ("./" or "../") are honored.
		// A bare "foo/bar" is ambiguous — reject so the user can
		// disambiguate with "./foo/bar" (relative) or "/foo/bar"
		// (absolute).
		if !strings.HasPrefix(raw, "./") && !strings.HasPrefix(raw, "../") && raw != "." && raw != ".." {
			return "", fmt.Errorf(
				"invalid rule %q: slash-containing inputs must be absolute (/…), tilde (~/…), or explicitly relative (./… or ../…)",
				raw,
			)
		}
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve cwd: %w", err)
		}
		raw = filepath.Join(cwd, raw)
	}

	// Best-effort symlink resolution so the stored rule matches the
	// canonicalized project_dir keys written by the cache. Skip on
	// error (path may not exist yet — prophylactic rules are legal).
	if resolved, err := filepath.EvalSymlinks(raw); err == nil {
		raw = resolved
	}
	return filepath.Clean(raw), nil
}

func runExclude(matcher *excludes.Matcher, rule string) {
	if err := matcher.Add(rule); err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard exclude: %v\n", err)
		os.Exit(1)
	}

	// DB cleanup: every project_dir already carrying alerts that the
	// (now-augmented) matcher matches gets wiped, in both project_alerts
	// and project_acks. Global acks (project_dir="*") are preserved by
	// ClearProjectAcks's canonicalization behavior.
	wiped, err := wipeMatchedRows(matcher)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard exclude: wipe cache: %v\n", err)
		// Don't fail the whole command — the rule is already persisted
		// and the daemon will honor it on next scan. Just surface the
		// error so the user knows manual cleanup may be needed.
	}

	fmt.Printf("Excluded %s (wiped %d project(s) from cache)\n", rule, wiped)
}

func runUnexclude(matcher *excludes.Matcher, rule string) {
	removed, err := matcher.Remove(rule)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard unexclude: %v\n", err)
		os.Exit(1)
	}
	if !removed {
		// Surface the no-op explicitly so a typo (or a rule pointing
		// at a default, which users can't remove) doesn't look like
		// it succeeded. Exit non-zero so scripts can detect it.
		fmt.Fprintf(os.Stderr, "pdmcguard unexclude: no such rule %q\n", rule)
		os.Exit(1)
	}
	// No cache cleanup on unexclude — the daemon's next scan will
	// re-populate the project_alerts rows that were wiped on the
	// original exclude. Reconcile the sentinel in case there were
	// suppressed alerts that should now tick the flag.
	if store, err := openExcludeCacheStore(); err == nil && store != nil {
		sync.ReconcileAlertSentinel(store)
		store.Close()
	}
	fmt.Printf("Unexcluded %s\n", rule)
}

// wipeMatchedRows runs after a successful Add, walks every distinct
// project_dir in the cache, and drops rows (alerts + per-project acks)
// for paths the matcher now covers. Reconciles the sentinel once at
// the end so a fully-silenced machine clears its alert flag.
func wipeMatchedRows(matcher *excludes.Matcher) (int, error) {
	store, err := openExcludeCacheStore()
	if err != nil {
		return 0, err
	}
	if store == nil {
		return 0, nil
	}
	defer store.Close()

	dirs, err := store.ListProjectDirs()
	if err != nil {
		return 0, err
	}

	wiped := 0
	for _, d := range dirs {
		if !matcher.Matches(d) {
			continue
		}
		if err := store.ClearProjectAlerts(d); err != nil {
			return wiped, err
		}
		if err := store.ClearProjectAcks(d); err != nil {
			return wiped, err
		}
		wiped++
	}

	sync.ReconcileAlertSentinel(store)
	return wiped, nil
}

func runListExcludes(matcher *excludes.Matcher) {
	rules := matcher.UserRules()
	if len(rules) == 0 && len(excludes.Defaults) == 0 {
		fmt.Println("No exclusion rules.")
		return
	}

	if len(rules) == 0 {
		fmt.Println("No user rules. Built-in defaults:")
	} else {
		fmt.Println("User rules:")
		for _, r := range rules {
			fmt.Printf("  %s\n", r)
		}
		fmt.Println("Built-in defaults (always active):")
	}
	for _, d := range excludes.Defaults {
		fmt.Printf("  %s  [default]\n", d)
	}
}
