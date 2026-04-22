// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnerGcorp/pdmcguard/internal/cache"
	"github.com/AnerGcorp/pdmcguard/internal/daemon"
	"github.com/AnerGcorp/pdmcguard/internal/excludes"
	"github.com/AnerGcorp/pdmcguard/internal/sync"
)

// fakeQueue is a minimal queueHandle for the unit tests. It avoids
// opening a real SQLite queue DB — those tests already exist in
// internal/sync; here we just need to verify doctor's classification
// logic (OK / WARN / FAIL by depth).
type fakeQueue struct {
	n   int
	err error
}

func (f *fakeQueue) Len() (int, error) { return f.n, f.err }
func (f *fakeQueue) Close() error      { return nil }

// newFakeQueueDep wraps a fakeQueue in the exact shape openQueue
// returns so callers can plug it straight into doctorDeps.
func newFakeQueueDep(n int) func() (*queueHandle, error) {
	return func() (*queueHandle, error) {
		var h queueHandle = &fakeQueue{n: n}
		return &h, nil
	}
}

// baseDeps builds a minimal doctorDeps that makes every check default
// to a sensible OK so individual tests only need to override the
// dep(s) they care about. dir is a test-owned temp dir that stands in
// for ~/.pdmcguard.
func baseDeps(t *testing.T, dir string) doctorDeps {
	t.Helper()
	bin := filepath.Join(dir, "bin", "pdmcguard")
	return doctorDeps{
		configDir:        func() string { return dir },
		installedBinPath: func() string { return bin },
		lookPath:         func(string) (string, error) { return bin, nil },
		serviceInstalled: func() bool { return true },
		detectShell:      func() string { return "zsh" },
		inspectHook: func(shell string) (daemon.HookInspection, error) {
			return daemon.HookInspection{
				RCPath:     filepath.Join(dir, ".zshrc"),
				Shell:      shell,
				Exists:     true,
				Present:    true,
				PathLineOK: true,
				EvalLineOK: true,
			}, nil
		},
		loadCredentials: func() (*sync.Credentials, error) {
			return &sync.Credentials{APIURL: "https://example.test", AccessToken: "tok"}, nil
		},
		openCache:       func() (*cache.Store, error) { return nil, nil },
		openQueue:       func() (*queueHandle, error) { return nil, nil },
		sentinelPath:    func() string { return filepath.Join(dir, "alerts.flag") },
		inspectExcludes: func(string) (excludes.InspectResult, error) { return excludes.InspectResult{}, nil },
	}
}

// TestCheckConfigDir_Missing asserts that a brand-new machine with no
// ~/.pdmcguard reports FAIL, because that's an install-never-ran
// signal and scripts should treat it as broken.
func TestCheckConfigDir_Missing(t *testing.T) {
	parent := t.TempDir()
	missing := filepath.Join(parent, "nope")
	deps := baseDeps(t, missing)

	r := checkConfigDir(deps)
	if r.status != statusFail {
		t.Errorf("missing config dir: status = %v, want FAIL", r.status)
	}
}

// TestCheckConfigDir_OK is the happy path — the temp dir exists.
func TestCheckConfigDir_OK(t *testing.T) {
	dir := t.TempDir()
	r := checkConfigDir(baseDeps(t, dir))
	if r.status != statusOK {
		t.Errorf("present config dir: status = %v, want OK", r.status)
	}
}

// TestCheckInstalledBinary exercises the three states: missing
// (FAIL), present but not executable (FAIL), present and +x (OK).
func TestCheckInstalledBinary(t *testing.T) {
	dir := t.TempDir()
	deps := baseDeps(t, dir)
	bin := deps.installedBinPath()

	// Missing.
	if r := checkInstalledBinary(deps); r.status != statusFail {
		t.Errorf("missing binary: status = %v, want FAIL", r.status)
	}

	// Present but not executable.
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := checkInstalledBinary(deps); r.status != statusFail {
		t.Errorf("non-exec binary: status = %v, want FAIL", r.status)
	}

	// Executable.
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if r := checkInstalledBinary(deps); r.status != statusOK {
		t.Errorf("exec binary: status = %v, want OK", r.status)
	}
}

// TestCheckBinaryOnPATH covers three dispositions: not on PATH (FAIL),
// resolves elsewhere (WARN — stale global shadow), resolves to the
// installed copy (OK).
func TestCheckBinaryOnPATH(t *testing.T) {
	dir := t.TempDir()
	deps := baseDeps(t, dir)

	deps.lookPath = func(string) (string, error) { return "", errors.New("not found") }
	if r := checkBinaryOnPATH(deps); r.status != statusFail {
		t.Errorf("not-on-PATH: status = %v, want FAIL", r.status)
	}

	deps.lookPath = func(string) (string, error) { return "/usr/local/bin/pdmcguard", nil }
	if r := checkBinaryOnPATH(deps); r.status != statusWarn {
		t.Errorf("shadow: status = %v, want WARN", r.status)
	}

	deps.lookPath = func(string) (string, error) { return deps.installedBinPath(), nil }
	if r := checkBinaryOnPATH(deps); r.status != statusOK {
		t.Errorf("installed: status = %v, want OK", r.status)
	}
}

// TestCheckShellHook maps HookInspection into verdicts. Partial blocks
// must be FAIL so a user staring at a half-broken rc file knows it.
func TestCheckShellHook(t *testing.T) {
	dir := t.TempDir()
	deps := baseDeps(t, dir)

	// Missing rc file → FAIL
	deps.inspectHook = func(string) (daemon.HookInspection, error) {
		return daemon.HookInspection{RCPath: "/tmp/nope"}, nil
	}
	if r := checkShellHook(deps); r.status != statusFail {
		t.Errorf("missing rc: status = %v, want FAIL", r.status)
	}

	// Exists but no block → FAIL
	deps.inspectHook = func(string) (daemon.HookInspection, error) {
		return daemon.HookInspection{RCPath: "/tmp/x", Exists: true}, nil
	}
	if r := checkShellHook(deps); r.status != statusFail {
		t.Errorf("no block: status = %v, want FAIL", r.status)
	}

	// Block present but missing eval line → FAIL
	deps.inspectHook = func(string) (daemon.HookInspection, error) {
		return daemon.HookInspection{RCPath: "/tmp/x", Exists: true, Present: true, PathLineOK: true}, nil
	}
	r := checkShellHook(deps)
	if r.status != statusFail {
		t.Errorf("partial block: status = %v, want FAIL", r.status)
	}
	if !strings.Contains(r.message, "eval hook-init") {
		t.Errorf("partial-block message should name missing eval line, got %q", r.message)
	}

	// All good → OK
	deps.inspectHook = func(string) (daemon.HookInspection, error) {
		return daemon.HookInspection{
			RCPath: "/tmp/x", Exists: true, Present: true, PathLineOK: true, EvalLineOK: true,
		}, nil
	}
	if r := checkShellHook(deps); r.status != statusOK {
		t.Errorf("intact: status = %v, want OK", r.status)
	}

	// InspectHook error → FAIL
	deps.inspectHook = func(string) (daemon.HookInspection, error) {
		return daemon.HookInspection{RCPath: "/tmp/x"}, errors.New("read failed")
	}
	if r := checkShellHook(deps); r.status != statusFail {
		t.Errorf("inspect error: status = %v, want FAIL", r.status)
	}
}

// TestCheckCredentials classifies all three states. ErrNoCredentials is
// WARN not FAIL — offline mode is a legitimate user choice.
func TestCheckCredentials(t *testing.T) {
	dir := t.TempDir()
	deps := baseDeps(t, dir)

	// Happy path.
	if r := checkCredentials(deps); r.status != statusOK {
		t.Errorf("logged in: status = %v, want OK", r.status)
	}

	// Offline.
	deps.loadCredentials = func() (*sync.Credentials, error) { return nil, sync.ErrNoCredentials }
	if r := checkCredentials(deps); r.status != statusWarn {
		t.Errorf("offline: status = %v, want WARN", r.status)
	}

	// Malformed — any other error.
	deps.loadCredentials = func() (*sync.Credentials, error) { return nil, errors.New("json: malformed") }
	if r := checkCredentials(deps); r.status != statusFail {
		t.Errorf("malformed creds: status = %v, want FAIL", r.status)
	}
}

// TestCheckCache_NoFileYet: a brand-new install with no cache.db is
// WARN — the daemon just hasn't run yet. Still surface it so a user
// who expected populated data knows why things look empty.
func TestCheckCache_NoFileYet(t *testing.T) {
	dir := t.TempDir()
	deps := baseDeps(t, dir)
	if r := checkCache(deps); r.status != statusWarn {
		t.Errorf("no cache: status = %v, want WARN", r.status)
	}
}

// TestCheckCacheIntegrity_OK opens a real cache store against a temp
// path, runs the integrity check, and expects "ok". This is the one
// test that touches SQLite — the cheaper alternative (stub
// IntegrityCheck) would bypass the call-path we actually ship.
func TestCheckCacheIntegrity_OK(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.db")
	store, err := cache.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	deps := baseDeps(t, dir)
	// Re-open fresh per call (doctor closes after each check).
	deps.openCache = func() (*cache.Store, error) { return cache.Open(dbPath) }

	r := checkCacheIntegrity(deps)
	if r.status != statusOK {
		t.Errorf("fresh cache integrity: status = %v, want OK (%q)", r.status, r.message)
	}
}

// TestCheckQueue covers depth-based classification. 0 = OK, >100 = WARN
// (long offline), error = FAIL.
func TestCheckQueue(t *testing.T) {
	dir := t.TempDir()
	deps := baseDeps(t, dir)

	deps.openQueue = newFakeQueueDep(0)
	if r := checkQueue(deps); r.status != statusOK {
		t.Errorf("empty queue: status = %v, want OK", r.status)
	}

	deps.openQueue = newFakeQueueDep(500)
	if r := checkQueue(deps); r.status != statusWarn {
		t.Errorf("backlogged queue: status = %v, want WARN", r.status)
	}
}

// TestCheckSentinel_Consistent verifies the four quadrants of the
// sentinel truth table. Drift is always WARN (self-healing).
func TestCheckSentinel_Consistent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.db")
	store, err := cache.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()

	deps := baseDeps(t, dir)
	deps.openCache = func() (*cache.Store, error) { return cache.Open(dbPath) }
	deps.sentinelPath = func() string { return filepath.Join(dir, "alerts.flag") }

	// No critical, no flag → OK.
	if r := checkSentinel(deps); r.status != statusOK {
		t.Errorf("no-critical, no-flag: status = %v (%q), want OK", r.status, r.message)
	}

	// No critical, flag exists → WARN (drift).
	if err := os.WriteFile(deps.sentinelPath(), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if r := checkSentinel(deps); r.status != statusWarn {
		t.Errorf("stale-flag drift: status = %v (%q), want WARN", r.status, r.message)
	}

	// Insert a critical → flag+cache match → OK.
	os.Remove(deps.sentinelPath())
	func() {
		s, err := cache.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.UpsertProjectAlert(cache.ProjectAlert{
			ProjectDir: "/x", AdvisoryID: "A1", PackageName: "p",
			Ecosystem: "npm", Severity: "critical",
		}); err != nil {
			t.Fatal(err)
		}
	}()
	if err := os.WriteFile(deps.sentinelPath(), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if r := checkSentinel(deps); r.status != statusOK {
		t.Errorf("critical+flag: status = %v (%q), want OK", r.status, r.message)
	}

	// Critical present, flag missing → WARN (drift).
	os.Remove(deps.sentinelPath())
	if r := checkSentinel(deps); r.status != statusWarn {
		t.Errorf("missing-flag drift: status = %v (%q), want WARN", r.status, r.message)
	}
}

// TestCheckExcludes covers OK / WARN / FAIL via the inspect stub.
func TestCheckExcludes(t *testing.T) {
	dir := t.TempDir()
	deps := baseDeps(t, dir)

	deps.inspectExcludes = func(string) (excludes.InspectResult, error) {
		return excludes.InspectResult{ParsedRules: 3}, nil
	}
	if r := checkExcludes(deps); r.status != statusOK {
		t.Errorf("clean excludes: status = %v, want OK", r.status)
	}

	deps.inspectExcludes = func(string) (excludes.InspectResult, error) {
		return excludes.InspectResult{ParsedRules: 2, SkippedLines: []int{4, 7}}, nil
	}
	r := checkExcludes(deps)
	if r.status != statusWarn {
		t.Errorf("skipped lines: status = %v, want WARN", r.status)
	}
	if !strings.Contains(r.detail, "4, 7") {
		t.Errorf("WARN detail should list line numbers, got %q", r.detail)
	}

	deps.inspectExcludes = func(string) (excludes.InspectResult, error) {
		return excludes.InspectResult{}, errors.New("permission denied")
	}
	if r := checkExcludes(deps); r.status != statusFail {
		t.Errorf("unreadable: status = %v, want FAIL", r.status)
	}
}

// TestRunDoctor_AllOKReturnsZero is the end-to-end green path: every
// check reports OK and the runner exits 0 with a clean summary.
func TestRunDoctor_AllOKReturnsZero(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin", "pdmcguard")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(dir, "cache.db")
	s, err := cache.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	deps := baseDeps(t, dir)
	deps.openCache = func() (*cache.Store, error) { return cache.Open(dbPath) }
	deps.openQueue = newFakeQueueDep(0)

	buf := &bytes.Buffer{}
	code := runDoctor(buf, deps, false)
	if code != 0 {
		t.Errorf("all-green doctor exit = %d, want 0\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "Summary:") {
		t.Error("expected summary line")
	}
	if strings.Contains(buf.String(), "[FAIL]") {
		t.Errorf("no FAIL tag expected; got:\n%s", buf.String())
	}
}

// TestRunDoctor_FailExitsOne: one failing check → overall exit 1.
// Uses a missing binary as the trigger since that's a common real
// breakage and maps 1:1 to the FAIL path.
func TestRunDoctor_FailExitsOne(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cache.db")
	s, err := cache.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	deps := baseDeps(t, dir)
	// installedBinPath points at a file that doesn't exist.
	deps.installedBinPath = func() string { return filepath.Join(dir, "nope") }
	deps.openCache = func() (*cache.Store, error) { return cache.Open(dbPath) }
	deps.openQueue = newFakeQueueDep(0)

	buf := &bytes.Buffer{}
	code := runDoctor(buf, deps, false)
	if code != 1 {
		t.Errorf("doctor with FAIL exit = %d, want 1\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "[FAIL]") {
		t.Error("expected a [FAIL] row")
	}
}

// TestRunDoctor_WarnDoesNotFail: credentials offline is WARN, but the
// runner should still exit 0 so `pdmcguard doctor && ...` scripts
// survive the common "not logged in yet" case.
func TestRunDoctor_WarnDoesNotFail(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin", "pdmcguard")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "cache.db")
	s, err := cache.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	deps := baseDeps(t, dir)
	deps.loadCredentials = func() (*sync.Credentials, error) { return nil, sync.ErrNoCredentials }
	deps.openCache = func() (*cache.Store, error) { return cache.Open(dbPath) }
	deps.openQueue = newFakeQueueDep(0)

	buf := &bytes.Buffer{}
	code := runDoctor(buf, deps, false)
	if code != 0 {
		t.Errorf("WARN-only doctor exit = %d, want 0", code)
	}
	if !strings.Contains(buf.String(), "[WARN]") {
		t.Error("expected at least one [WARN] row")
	}
	if strings.Contains(buf.String(), "[FAIL]") {
		t.Errorf("unexpected [FAIL] in WARN-only run:\n%s", buf.String())
	}
}

// TestRunDoctor_VerboseShowsDetail: the --verbose flag promotes detail
// lines from the skipped-excludes branch into the output. Without
// --verbose, the same run should omit them.
func TestRunDoctor_VerboseShowsDetail(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin", "pdmcguard")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	deps := baseDeps(t, dir)
	deps.openQueue = newFakeQueueDep(0)
	deps.inspectExcludes = func(string) (excludes.InspectResult, error) {
		return excludes.InspectResult{ParsedRules: 1, SkippedLines: []int{3}}, nil
	}

	var plain, verbose bytes.Buffer
	runDoctor(&plain, deps, false)
	runDoctor(&verbose, deps, true)

	if strings.Contains(plain.String(), "Skipped line numbers") {
		t.Error("plain output should omit detail block")
	}
	if !strings.Contains(verbose.String(), "Skipped line numbers: 3") {
		t.Errorf("verbose output should include detail; got:\n%s", verbose.String())
	}
}

// sanityFmtOutput is a smoke guard: ensure printCheck produces a tag
// we can grep in CI. Fails loudly if someone changes the tag format.
func TestPrintCheck_Tags(t *testing.T) {
	cases := map[checkStatus]string{
		statusOK:   "[OK]",
		statusWarn: "[WARN]",
		statusFail: "[FAIL]",
	}
	for s, want := range cases {
		var buf bytes.Buffer
		printCheck(&buf, checkResult{name: "x", status: s, message: "m"}, false, false)
		if !strings.Contains(buf.String(), want) {
			t.Errorf("status %v: missing %q in %q", s, want, buf.String())
		}
	}
	// Compile-time check that fmt.Sprintf is still imported where used.
	_ = fmt.Sprintf
}
