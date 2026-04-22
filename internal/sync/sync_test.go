// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package sync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AnerGcorp/pdmcguard/internal/cache"
)

func TestResolveLockPathLockFile(t *testing.T) {
	dir := t.TempDir()
	goSum := filepath.Join(dir, "go.sum")
	os.WriteFile(goSum, []byte("test"), 0o644)

	got := resolveLockPath(goSum, "go")
	if got != goSum {
		t.Errorf("expected %q, got %q", goSum, got)
	}
}

func TestResolveLockPathManifestRedirect(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")
	goSum := filepath.Join(dir, "go.sum")
	os.WriteFile(goMod, []byte("module test"), 0o644)
	os.WriteFile(goSum, []byte("test"), 0o644)

	got := resolveLockPath(goMod, "go")
	if got != goSum {
		t.Errorf("expected %q, got %q", goSum, got)
	}
}

func TestResolveLockPathNoLockFile(t *testing.T) {
	dir := t.TempDir()
	goMod := filepath.Join(dir, "go.mod")
	os.WriteFile(goMod, []byte("module test"), 0o644)

	got := resolveLockPath(goMod, "go")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestResolveLockPathNpmFallbackYarn(t *testing.T) {
	dir := t.TempDir()
	pkgJSON := filepath.Join(dir, "package.json")
	yarnLock := filepath.Join(dir, "yarn.lock")
	os.WriteFile(pkgJSON, []byte("{}"), 0o644)
	os.WriteFile(yarnLock, []byte("test"), 0o644)

	got := resolveLockPath(pkgJSON, "npm")
	if got != yarnLock {
		t.Errorf("expected %q (yarn fallback), got %q", yarnLock, got)
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("hello world"), 0o644)

	h1, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == "" {
		t.Fatal("hash is empty")
	}

	// Same content = same hash
	h2, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Error("same content should produce same hash")
	}

	// Different content = different hash
	os.WriteFile(path, []byte("hello world!"), 0o644)
	h3, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Error("different content should produce different hash")
	}
}

func TestHashString(t *testing.T) {
	h := hashString("/home/user/project")
	if h == "" {
		t.Fatal("hash is empty")
	}
	if len(h) != 64 { // SHA-256 hex
		t.Errorf("expected 64 char hex, got %d chars", len(h))
	}
}

func TestContentHashDedup(t *testing.T) {
	// Test that hashFile returns the same hash for identical content
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.txt")
	f2 := filepath.Join(dir, "b.txt")
	content := []byte("same content")
	os.WriteFile(f1, content, 0o644)
	os.WriteFile(f2, content, 0o644)

	h1, _ := hashFile(f1)
	h2, _ := hashFile(f2)
	if h1 != h2 {
		t.Error("identical content should produce identical hashes")
	}
}

// TestMetaKey_EcosystemSpecific guards the Stage 3 fix where metaKey went
// from "content_hash:<dir>" to "content_hash:<eco>:<dir>". Without this,
// a polyglot project with both package.json and go.mod would clobber the
// other ecosystem's hash on every event, forcing needless re-classifies.
func TestMetaKey_EcosystemSpecific(t *testing.T) {
	dir := "/tmp/multi"
	npm := metaKey(dir, "npm")
	goKey := metaKey(dir, "go")

	if npm == goKey {
		t.Errorf("metaKey must differ per ecosystem: npm=%q go=%q", npm, goKey)
	}
	// Spot-check shape — test doesn't hard-code the exact format to avoid
	// coupling, but the key must embed both inputs.
	for _, want := range []string{"npm", "go", dir} {
		if want == "npm" && !contains(npm, want) {
			t.Errorf("npm key missing %q: %q", want, npm)
		}
		if want == "go" && !contains(goKey, want) {
			t.Errorf("go key missing %q: %q", want, goKey)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// newTestEngine builds a sync.Engine backed by a temp cache + queue with
// no API client (offline). Useful for tests that only care about the
// HandleChange pre-dispatch logic (hash dedup, enumeration) rather than
// the classifier roundtrip.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	cacheStore, err := cache.Open(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cacheStore.Close() })

	queuePath := filepath.Join(t.TempDir(), "queue.db")
	queue, err := OpenQueue(queuePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { queue.Close() })

	return &Engine{
		cache:  cacheStore,
		queue:  queue,
		online: false, // force the offline enqueue branch in HandleChange
	}
}

// TestBaselineScan_DedupHonorsMeta pre-seeds the content-hash meta row
// with the exact hash of the lockfile on disk, then runs BaselineScan.
// HandleChange must hit its dedup short-circuit before reaching the
// offline-queue branch — so the queue stays empty.
//
// This is the contract that makes daemon restarts cheap: if nothing
// changed since the previous run, baseline is a O(projects) walk with
// no work per project.
func TestBaselineScan_DedupHonorsMeta(t *testing.T) {
	e := newTestEngine(t)

	projDir := t.TempDir()
	goSumPath := filepath.Join(projDir, "go.sum")
	// A real-ish go.sum so lockfile.Parse returns non-empty pkgs and we
	// actually reach the dedup/offline branches in HandleChange.
	const goSum = "github.com/example/foo v1.0.0 h1:abc=\n" +
		"github.com/example/foo v1.0.0/go.mod h1:abc=\n"
	if err := os.WriteFile(goSumPath, []byte(goSum), 0o644); err != nil {
		t.Fatal(err)
	}
	// EnumeratePDMCFiles prefers go.sum over go.mod, but resolveLockPath
	// also wants go.sum to exist — having only go.sum keeps the path clean.

	hash, err := hashFile(goSumPath)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate what a previous run's syncProject would have written.
	if err := e.cache.SetMeta(metaKey(projDir, "go"), hash); err != nil {
		t.Fatal(err)
	}

	stats := e.BaselineScan([]string{projDir}, nil)

	if stats.Total != 1 {
		t.Fatalf("Total = %d, want 1", stats.Total)
	}
	if stats.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (dedup should win)", stats.Skipped)
	}
	if stats.Classified != 0 {
		t.Errorf("Classified = %d, want 0", stats.Classified)
	}
	// Crucially: nothing queued because HandleChange returned at the dedup
	// check before reaching the offline-queue branch.
	n, _ := e.queue.Len()
	if n != 0 {
		t.Errorf("queue depth = %d, want 0 (dedup should short-circuit before enqueue)", n)
	}
}

// TestBaselineScan_OfflineEnqueuesWithoutMeta is the mirror image: no
// pre-seeded meta, engine offline. HandleChange must pass dedup, parse,
// and enqueue — confirming that a fresh daemon on a new machine does
// capture the work even when the classifier API is unreachable.
func TestBaselineScan_OfflineEnqueuesWithoutMeta(t *testing.T) {
	e := newTestEngine(t)

	projDir := t.TempDir()
	goSumPath := filepath.Join(projDir, "go.sum")
	const goSum = "github.com/example/foo v1.0.0 h1:abc=\n" +
		"github.com/example/foo v1.0.0/go.mod h1:abc=\n"
	if err := os.WriteFile(goSumPath, []byte(goSum), 0o644); err != nil {
		t.Fatal(err)
	}

	stats := e.BaselineScan([]string{projDir}, nil)

	if stats.Total != 1 {
		t.Fatalf("Total = %d, want 1", stats.Total)
	}
	// Offline path does not update meta, so before == after (both empty)
	// and BaselineScan counts this as Skipped even though work happened.
	// Document this subtlety: stats reflect dedup decisions, not work
	// done. Integration test via queue depth is the real signal.
	n, _ := e.queue.Len()
	if n != 1 {
		t.Errorf("queue depth = %d, want 1 (offline run should enqueue)", n)
	}
}

// TestBaselineScan_ReconcilesSentinel guards the post-baseline
// updateAlertSentinel call. Scenario: a critical alert exists in the
// DB (e.g. left over from a previous online session) but the sentinel
// flag file is missing (manual deletion, ~/.pdmcguard recreated, etc.).
// Without the reconcile, the shell hook stat()s a missing flag and
// short-circuits silently — which is exactly the bug that surfaced
// during manual E2E of Stage 3.
func TestBaselineScan_ReconcilesSentinel(t *testing.T) {
	// Redirect config.Dir() away from the real ~/.pdmcguard.
	t.Setenv("HOME", t.TempDir())

	e := newTestEngine(t)

	// Pre-seed a critical alert directly in the DB — simulates leftover
	// state from a previous online run.
	if err := e.cache.UpsertProjectAlert(cache.ProjectAlert{
		ProjectDir:  "/tmp/somewhere",
		AdvisoryID:  "TEST-CRITICAL",
		PackageName: "demo",
		Ecosystem:   "npm",
		Severity:    "critical",
		Summary:     "reconcile probe",
	}); err != nil {
		t.Fatal(err)
	}

	// Sentinel must not exist before baseline — that's the bug state.
	sentinel := AlertSentinelFile()
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("sentinel should be absent before baseline; stat err=%v", err)
	}

	// Run baseline with no dirs — enumeration yields zero events, so the
	// reconcile runs without touching HandleChange at all. Proves the
	// sentinel update is unconditional post-loop, not a side effect.
	e.BaselineScan(nil, nil)

	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("sentinel not written after BaselineScan: %v", err)
	}
}
