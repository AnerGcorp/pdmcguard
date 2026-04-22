// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AnerGcorp/pdmcguard/internal/cache"
	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/daemon"
	"github.com/AnerGcorp/pdmcguard/internal/excludes"
	"github.com/AnerGcorp/pdmcguard/internal/sync"
	"github.com/mattn/go-isatty"
)

// checkStatus enumerates the three-level verdict a doctor check can
// return. Values are ordered so `max(a, b)` gives the overall severity,
// which is how the runner computes the summary exit code.
type checkStatus int

const (
	statusOK checkStatus = iota
	statusWarn
	statusFail
)

// checkResult is one row of the doctor report. name is the left-column
// label; message is the one-line verdict; detail is optional multi-line
// context only rendered under --verbose (skipped-line numbers, rc
// paths, sentinel actual-vs-expected etc.).
type checkResult struct {
	name    string
	status  checkStatus
	message string
	detail  string
}

// doctorDeps carries the injection points the CLI uses in production
// and tests override. Keeping these as a struct (rather than a pile of
// package-level vars) makes it easy to build an in-memory fixture in
// one place and hand it to runDoctor.
type doctorDeps struct {
	// configDir returns ~/.pdmcguard (or the test's temp dir).
	configDir func() string
	// installedBinPath is the absolute path of the copy the installer
	// dropped in place. Doctor compares $PATH resolution and os.Stat
	// against this.
	installedBinPath func() string
	// lookPath mirrors exec.LookPath so tests can simulate "not on
	// PATH" or "PATH shadowed by a stale global".
	lookPath func(string) (string, error)
	// serviceInstalled is NewServiceManager().IsInstalled() behind a
	// func so tests don't have to mount launchd.
	serviceInstalled func() bool
	// detectShell is daemon.DetectShell indirected for tests.
	detectShell func() string
	// inspectHook is daemon.InspectHook indirected.
	inspectHook func(string) (daemon.HookInspection, error)
	// loadCredentials is sync.LoadCredentials indirected.
	loadCredentials func() (*sync.Credentials, error)
	// openCache opens the cache DB. Returning nil store (no error) is
	// the "no cache yet" signal — doctor treats that as not-fatal for
	// a very fresh install, but WARN so the user notices.
	openCache func() (*cache.Store, error)
	// openQueue mirrors sync.OpenQueue.
	openQueue func() (*queueHandle, error)
	// sentinelPath is sync.AlertSentinelFile() indirected.
	sentinelPath func() string
	// inspectExcludes wraps excludes.Inspect.
	inspectExcludes func(string) (excludes.InspectResult, error)
}

// queueHandle is the subset of *sync.Queue that doctor needs. Declared
// as an interface so tests can plug a fake without opening a real DB.
type queueHandle interface {
	Len() (int, error)
	Close() error
}

// defaultDoctorDeps wires every dep to the production implementation.
// The only slightly awkward one is lookPath: exec.LookPath consults the
// process's $PATH, which is exactly what we want (doctor should inspect
// what the user's current shell sees, not a sanitized subset).
func defaultDoctorDeps() doctorDeps {
	return doctorDeps{
		configDir:        config.Dir,
		installedBinPath: func() string { return filepath.Join(config.Dir(), "bin", "pdmcguard") },
		lookPath:         exec.LookPath,
		serviceInstalled: func() bool { return daemon.NewServiceManager().IsInstalled() },
		detectShell:      daemon.DetectShell,
		inspectHook:      daemon.InspectHook,
		loadCredentials:  sync.LoadCredentials,
		openCache: func() (*cache.Store, error) {
			dbPath := config.FilePath("cache.db")
			if _, err := os.Stat(dbPath); os.IsNotExist(err) {
				return nil, nil
			}
			return cache.Open(dbPath)
		},
		openQueue: func() (*queueHandle, error) {
			dbPath := config.FilePath("queue.db")
			if _, err := os.Stat(dbPath); os.IsNotExist(err) {
				return nil, nil
			}
			q, err := sync.OpenQueue(dbPath)
			if err != nil {
				return nil, err
			}
			var h queueHandle = q
			return &h, nil
		},
		sentinelPath:    sync.AlertSentinelFile,
		inspectExcludes: excludes.Inspect,
	}
}

// cmdDoctor is the switch target wired into main.go. Parses flags, runs
// the checks with the production deps, writes the report to stdout, and
// exits 1 iff any FAIL was emitted. WARN does not bump the exit code —
// scripts that want to fail on WARN can grep for it.
func cmdDoctor(args []string) {
	verbose := false
	for _, a := range args {
		switch a {
		case "-v", "--verbose":
			verbose = true
		case "-h", "--help":
			fmt.Println("usage: pdmcguard doctor [--verbose]")
			return
		default:
			fmt.Fprintf(os.Stderr, "pdmcguard doctor: unexpected arg %q\n", a)
			os.Exit(2)
		}
	}

	code := runDoctor(os.Stdout, defaultDoctorDeps(), verbose)
	os.Exit(code)
}

// runDoctor is the testable body. Returns 0 for "all OK / WARN only",
// 1 for "at least one FAIL". Splitting out the writer + deps means
// unit tests can assert on the report text without going near stdout or
// os.Exit.
func runDoctor(out io.Writer, deps doctorDeps, verbose bool) int {
	fmt.Fprintln(out, "pdmcguard doctor — checking...")
	fmt.Fprintln(out)

	checks := []checkResult{
		checkConfigDir(deps),
		checkInstalledBinary(deps),
		checkBinaryOnPATH(deps),
		checkService(deps),
		checkShellHook(deps),
		checkCredentials(deps),
		checkCache(deps),
		checkCacheIntegrity(deps),
		checkQueue(deps),
		checkSentinel(deps),
		checkExcludes(deps),
	}

	colorize := isTTYWriter(out)
	var okN, warnN, failN int
	for _, r := range checks {
		printCheck(out, r, verbose, colorize)
		switch r.status {
		case statusOK:
			okN++
		case statusWarn:
			warnN++
		case statusFail:
			failN++
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "Summary: %d OK, %d WARN, %d FAIL\n", okN, warnN, failN)
	if failN > 0 {
		return 1
	}
	return 0
}

// isTTYWriter reports whether out is a terminal stdout that should be
// colorized. Piped output / files / the test writer all return false so
// the ASCII tags remain grep-friendly.
//
// Pulled out as a var so tests can force the non-TTY branch explicitly,
// matching the precheck.go convention for stderrIsTTY.
var isTTYWriter = func(out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	fd := f.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// printCheck renders one row. The column alignment (name padded to 20
// chars after a 7-char status tag) is chosen so the output lines up at
// ~80 cols for every realistic label length.
func printCheck(out io.Writer, r checkResult, verbose, colorize bool) {
	tag := tagFor(r.status, colorize)
	fmt.Fprintf(out, "%s %-20s %s\n", tag, r.name, r.message)
	if verbose && r.detail != "" {
		for _, line := range strings.Split(r.detail, "\n") {
			fmt.Fprintf(out, "         %s\n", line)
		}
	}
}

func tagFor(s checkStatus, colorize bool) string {
	const (
		green  = "\033[32m"
		yellow = "\033[33m"
		red    = "\033[31m"
		reset  = "\033[0m"
	)
	switch s {
	case statusOK:
		if colorize {
			return green + "[OK]  " + reset
		}
		return "[OK]  "
	case statusWarn:
		if colorize {
			return yellow + "[WARN]" + reset
		}
		return "[WARN]"
	default:
		if colorize {
			return red + "[FAIL]" + reset
		}
		return "[FAIL]"
	}
}

// ── Checks ─────────────────────────────────────────────────────────────────
//
// Each check is a pure function over deps returning a checkResult.
// Order chosen deliberately: fundamental-install issues first (config
// dir, binary, PATH, service) so a misconfigured machine shows its
// blocker at the top of the report, then the data-plane checks.

func checkConfigDir(d doctorDeps) checkResult {
	dir := d.configDir()
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return checkResult{
				name:    "config dir",
				status:  statusFail,
				message: fmt.Sprintf("%s does not exist (run 'pdmcguard install')", dir),
			}
		}
		return checkResult{
			name:    "config dir",
			status:  statusFail,
			message: fmt.Sprintf("%s: %v", dir, err),
		}
	}
	if !info.IsDir() {
		return checkResult{
			name:    "config dir",
			status:  statusFail,
			message: fmt.Sprintf("%s exists but is not a directory", dir),
		}
	}
	return checkResult{
		name:    "config dir",
		status:  statusOK,
		message: fmt.Sprintf("%s present", dir),
	}
}

func checkInstalledBinary(d doctorDeps) checkResult {
	bin := d.installedBinPath()
	info, err := os.Stat(bin)
	if err != nil {
		if os.IsNotExist(err) {
			return checkResult{
				name:    "installed binary",
				status:  statusFail,
				message: fmt.Sprintf("%s not found (run 'pdmcguard install')", bin),
			}
		}
		return checkResult{
			name:    "installed binary",
			status:  statusFail,
			message: fmt.Sprintf("%s: %v", bin, err),
		}
	}
	if info.Mode().Perm()&0o111 == 0 {
		return checkResult{
			name:    "installed binary",
			status:  statusFail,
			message: fmt.Sprintf("%s is not executable (mode %v)", bin, info.Mode()),
		}
	}
	return checkResult{
		name:    "installed binary",
		status:  statusOK,
		message: fmt.Sprintf("%s (exec)", bin),
	}
}

// checkBinaryOnPATH distinguishes three cases: resolves to the
// installed copy (OK), resolves to something else (WARN — a global
// `pdmcguard` is shadowing us), not on PATH at all (FAIL). We resolve
// symlinks on both sides before comparing so ~/.pdmcguard/bin/pdmcguard
// pointing to the same inode as /usr/local/bin/pdmcguard still reports
// OK instead of phantom WARN.
func checkBinaryOnPATH(d doctorDeps) checkResult {
	resolved, err := d.lookPath("pdmcguard")
	if err != nil {
		return checkResult{
			name:    "binary on PATH",
			status:  statusFail,
			message: "pdmcguard not on $PATH (reopen shell or run 'pdmcguard install')",
		}
	}
	want := d.installedBinPath()
	a, _ := filepath.EvalSymlinks(resolved)
	b, _ := filepath.EvalSymlinks(want)
	if a == "" {
		a = resolved
	}
	if b == "" {
		b = want
	}
	if a == b {
		return checkResult{
			name:    "binary on PATH",
			status:  statusOK,
			message: "resolves to installed location",
			detail:  resolved,
		}
	}
	return checkResult{
		name:   "binary on PATH",
		status: statusWarn,
		message: fmt.Sprintf("resolves to %s, not %s (stale install?)",
			resolved, want),
	}
}

func checkService(d doctorDeps) checkResult {
	if d.serviceInstalled() {
		return checkResult{
			name:    "service",
			status:  statusOK,
			message: "installed",
		}
	}
	return checkResult{
		name:    "service",
		status:  statusFail,
		message: "not installed (run 'pdmcguard install')",
	}
}

// checkShellHook interprets the structured HookInspection. Missing rc
// file and totally-stripped block are both FAIL (user thinks they have
// the hook when they don't). A half-block or a block missing the eval
// line is also FAIL — the hook is incapable of firing the pre-prompt
// check. Only a fully-intact block is OK.
func checkShellHook(d doctorDeps) checkResult {
	shell := d.detectShell()
	ins, err := d.inspectHook(shell)
	if err != nil {
		return checkResult{
			name:    "shell hook",
			status:  statusFail,
			message: fmt.Sprintf("read %s failed: %v", ins.RCPath, err),
		}
	}
	if !ins.Exists {
		return checkResult{
			name:    "shell hook",
			status:  statusFail,
			message: fmt.Sprintf("rc file %s not found (run 'pdmcguard install')", ins.RCPath),
		}
	}
	if !ins.Present {
		return checkResult{
			name:    "shell hook",
			status:  statusFail,
			message: fmt.Sprintf("hook block missing from %s (run 'pdmcguard install')", ins.RCPath),
		}
	}
	if !ins.PathLineOK || !ins.EvalLineOK {
		var missing []string
		if !ins.PathLineOK {
			missing = append(missing, "PATH export")
		}
		if !ins.EvalLineOK {
			missing = append(missing, "eval hook-init")
		}
		return checkResult{
			name:    "shell hook",
			status:  statusFail,
			message: fmt.Sprintf("%s: block present but missing %s", ins.RCPath, strings.Join(missing, " and ")),
		}
	}
	return checkResult{
		name:    "shell hook",
		status:  statusOK,
		message: fmt.Sprintf("intact in %s (%s)", ins.RCPath, shell),
		detail:  fmt.Sprintf("PATH line + eval line present"),
	}
}

// checkCredentials maps the three sync-login states: logged in (OK),
// not logged in yet (WARN — offline mode is a legit choice, not broken),
// malformed credentials file (FAIL — user will silently be offline with
// no idea why).
func checkCredentials(d doctorDeps) checkResult {
	_, err := d.loadCredentials()
	if err == nil {
		return checkResult{
			name:    "credentials",
			status:  statusOK,
			message: "logged in",
		}
	}
	if errors.Is(err, sync.ErrNoCredentials) {
		return checkResult{
			name:    "credentials",
			status:  statusWarn,
			message: "offline mode (run 'pdmcguard login' to sync)",
		}
	}
	return checkResult{
		name:    "credentials",
		status:  statusFail,
		message: fmt.Sprintf("credentials.json unreadable: %v", err),
	}
}

func checkCache(d doctorDeps) checkResult {
	store, err := d.openCache()
	if err != nil {
		return checkResult{
			name:    "cache",
			status:  statusFail,
			message: fmt.Sprintf("cache.db unreachable: %v", err),
		}
	}
	if store == nil {
		// No cache yet — fresh install, daemon hasn't run. Not a
		// failure, but worth surfacing so a user who expects the
		// daemon to have populated it sees the reason it's silent.
		return checkResult{
			name:    "cache",
			status:  statusWarn,
			message: "no cache.db yet (start the daemon)",
		}
	}
	store.Close()
	return checkResult{
		name:    "cache",
		status:  statusOK,
		message: config.FilePath("cache.db") + " reachable",
	}
}

// checkCacheIntegrity runs SQLite's `PRAGMA integrity_check`. Returns
// OK iff the single "ok" row comes back — anything else (list of
// corrupt pages, or a query error) is FAIL with the first line as
// context. Skipped when the cache isn't present yet (already reported
// by checkCache). Uses cache.DB() — added alongside this feature so
// doctor doesn't poke SQLite through reflection.
func checkCacheIntegrity(d doctorDeps) checkResult {
	store, err := d.openCache()
	if err != nil {
		return checkResult{
			name:    "cache integrity",
			status:  statusFail,
			message: fmt.Sprintf("cache open failed: %v", err),
		}
	}
	if store == nil {
		return checkResult{
			name:    "cache integrity",
			status:  statusOK,
			message: "skipped (no cache.db)",
		}
	}
	defer store.Close()

	result, err := store.IntegrityCheck()
	if err != nil {
		return checkResult{
			name:    "cache integrity",
			status:  statusFail,
			message: fmt.Sprintf("PRAGMA integrity_check failed: %v", err),
		}
	}
	if result != "ok" {
		return checkResult{
			name:    "cache integrity",
			status:  statusFail,
			message: fmt.Sprintf("integrity_check = %q", result),
			detail:  "Run 'sqlite3 ~/.pdmcguard/cache.db \"PRAGMA integrity_check\"' for full report.",
		}
	}
	return checkResult{
		name:    "cache integrity",
		status:  statusOK,
		message: "PRAGMA integrity_check = ok",
	}
}

// checkQueue reports offline-sync backlog depth. A small queue on an
// offline machine is fine; > 100 pending items means the machine has
// been drifting for a while (either long-offline, or the daemon isn't
// draining). WARN rather than FAIL — data isn't lost, just stale.
func checkQueue(d doctorDeps) checkResult {
	qh, err := d.openQueue()
	if err != nil {
		return checkResult{
			name:    "queue",
			status:  statusFail,
			message: fmt.Sprintf("queue.db unreachable: %v", err),
		}
	}
	if qh == nil {
		return checkResult{
			name:    "queue",
			status:  statusOK,
			message: "no queue yet (no writes)",
		}
	}
	q := *qh
	defer q.Close()
	n, err := q.Len()
	if err != nil {
		return checkResult{
			name:    "queue",
			status:  statusFail,
			message: fmt.Sprintf("queue length read: %v", err),
		}
	}
	if n > 100 {
		return checkResult{
			name:    "queue",
			status:  statusWarn,
			message: fmt.Sprintf("%d pending items (long offline?)", n),
		}
	}
	return checkResult{
		name:    "queue",
		status:  statusOK,
		message: fmt.Sprintf("%d pending", n),
	}
}

// checkSentinel verifies the alerts.flag file matches the cache's
// HasAnyCritical truth value. Drift is WARN, not FAIL: the sync engine
// re-reconciles on every mutation, so drift is transient and
// self-healing — worst case, one extra/missing shell-hook banner until
// the next ack/unack or daemon tick. FAIL only if the cache is
// unreadable (already caught by checkCache, but repeat defensively so
// this check is self-contained).
func checkSentinel(d doctorDeps) checkResult {
	store, err := d.openCache()
	if err != nil || store == nil {
		return checkResult{
			name:    "sentinel",
			status:  statusOK,
			message: "skipped (no cache)",
		}
	}
	defer store.Close()

	hasAny, err := store.HasAnyCritical()
	if err != nil {
		return checkResult{
			name:    "sentinel",
			status:  statusFail,
			message: fmt.Sprintf("HasAnyCritical: %v", err),
		}
	}
	path := d.sentinelPath()
	_, statErr := os.Stat(path)
	sentinelExists := statErr == nil

	switch {
	case hasAny && sentinelExists:
		return checkResult{
			name:    "sentinel",
			status:  statusOK,
			message: "consistent with cache (critical present, flag set)",
		}
	case !hasAny && !sentinelExists:
		return checkResult{
			name:    "sentinel",
			status:  statusOK,
			message: "consistent with cache (no critical, no flag)",
		}
	case hasAny && !sentinelExists:
		return checkResult{
			name:    "sentinel",
			status:  statusWarn,
			message: "cache has critical alerts but alerts.flag is missing",
			detail:  "Will self-heal on next daemon tick or ack. Run any `pdmcguard ack <id>` / `unack <id>` to reconcile immediately.",
		}
	default: // !hasAny && sentinelExists
		return checkResult{
			name:    "sentinel",
			status:  statusWarn,
			message: "alerts.flag exists but cache has no critical alerts",
			detail:  "Will self-heal on next daemon tick or ack.",
		}
	}
}

// checkExcludes audits the rules file. OK when every non-blank line
// parsed. WARN when some lines were silently dropped (the user's rule
// didn't land, but the daemon runs fine). FAIL only if the file exists
// but is unreadable.
func checkExcludes(d doctorDeps) checkResult {
	path := config.FilePath("excludes")
	res, err := d.inspectExcludes(path)
	if err != nil {
		return checkResult{
			name:    "excludes",
			status:  statusFail,
			message: fmt.Sprintf("%s unreadable: %v", path, err),
		}
	}
	if len(res.SkippedLines) > 0 {
		nums := make([]string, len(res.SkippedLines))
		for i, n := range res.SkippedLines {
			nums[i] = fmt.Sprintf("%d", n)
		}
		return checkResult{
			name:   "excludes",
			status: statusWarn,
			message: fmt.Sprintf("%d rules, %d line(s) silently skipped",
				res.ParsedRules, len(res.SkippedLines)),
			detail: fmt.Sprintf("Skipped line numbers: %s. Re-run `pdmcguard exclude <path>` with an absolute or ./-prefixed path.",
				strings.Join(nums, ", ")),
		}
	}
	return checkResult{
		name:    "excludes",
		status:  statusOK,
		message: fmt.Sprintf("%d rules, 0 skipped", res.ParsedRules),
	}
}
