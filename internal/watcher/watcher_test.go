// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package watcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AnerGcorp/pdmcguard/internal/excludes"
)

func TestWatcher_PDMCEvent(t *testing.T) {
	w, err := New(nil, nil) // no exclude store
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	dir := t.TempDir()
	if _, err := w.Add(dir); err != nil {
		t.Fatal(err)
	}

	// Write a PDMC file
	target := filepath.Join(dir, "package.json")
	if err := os.WriteFile(target, []byte(`{"name":"test"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-w.Events:
		if ev.Filename != "package.json" {
			t.Errorf("got filename %q, want package.json", ev.Filename)
		}
		if ev.Ecosystem != "npm" {
			t.Errorf("got ecosystem %q, want npm", ev.Ecosystem)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for PDMC event")
	}
}

func TestWatcher_IgnoresNonPDMC(t *testing.T) {
	w, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	dir := t.TempDir()
	if _, err := w.Add(dir); err != nil {
		t.Fatal(err)
	}

	// Write a non-PDMC file
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("console.log('hi')"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-w.Events:
		t.Errorf("unexpected event for non-PDMC file: %+v", ev)
	case <-time.After(1 * time.Second):
		// Expected — no event
	}
}

func TestWatcher_Debounce(t *testing.T) {
	w, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	dir := t.TempDir()
	if _, err := w.Add(dir); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(dir, "go.mod")

	// Rapid writes — should collapse to a single event
	for i := 0; i < 5; i++ {
		os.WriteFile(target, []byte("module test\n"), 0o644)
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for debounce to fire
	var count int
	timeout := time.After(3 * time.Second)
	drain := time.After(1500 * time.Millisecond) // debounce(500ms) + margin
loop:
	for {
		select {
		case <-w.Events:
			count++
		case <-drain:
			break loop
		case <-timeout:
			break loop
		}
	}

	if count != 1 {
		t.Errorf("expected 1 debounced event, got %d", count)
	}
}

// TestWatcher_AddHonorsMatcher verifies that a directory covered by a
// user exclusion rule is refused at Add time: the call succeeds but
// reports added=false, and fsnotify never registers the directory, so
// subsequent file writes can't produce events.
func TestWatcher_AddHonorsMatcher(t *testing.T) {
	dir := t.TempDir()

	// Build a matcher with an absolute-prefix rule covering `dir`.
	rules := filepath.Join(t.TempDir(), "excludes")
	if err := os.WriteFile(rules, []byte(dir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := excludes.Load(rules)
	if err != nil {
		t.Fatal(err)
	}

	w, err := New(nil, m)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	added, err := w.Add(dir)
	if err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	if added {
		t.Fatal("Add should return false for matcher-excluded dir")
	}

	// A write into the unwatched dir must not produce an event.
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-w.Events:
		t.Errorf("unexpected event from excluded dir: %+v", ev)
	case <-time.After(800 * time.Millisecond):
		// expected: silence
	}
}

// TestWatchRoot_EmitsOnCreate verifies the runtime-discovery fast path:
// after registering a root, creating a new child directory should surface
// on RootCreates within one event tick. This is the signal runDaemon
// consumes to discover repos cloned after daemon start.
func TestWatchRoot_EmitsOnCreate(t *testing.T) {
	w, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	root := t.TempDir()
	if err := w.WatchRoot(root); err != nil {
		t.Fatalf("WatchRoot: %v", err)
	}

	newDir := filepath.Join(root, "new-project")
	if err := os.Mkdir(newDir, 0o755); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-w.RootCreates:
		if got != newDir {
			t.Errorf("RootCreates = %q, want %q", got, newDir)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RootCreates event")
	}
}

// TestWatchRoot_IgnoresHiddenDirs: `.git`, `.cache`, and similar dot-dirs
// should NOT trigger a RootCreates event. Bootstrap's walk filters them
// anyway, but filtering here keeps the channel signal-to-noise high when
// a user's tools create scratch dirs alongside projects.
func TestWatchRoot_IgnoresHiddenDirs(t *testing.T) {
	w, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	root := t.TempDir()
	if err := w.WatchRoot(root); err != nil {
		t.Fatal(err)
	}

	hidden := filepath.Join(root, ".tmp-scratch")
	if err := os.Mkdir(hidden, 0o755); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-w.RootCreates:
		t.Errorf("unexpected RootCreates for hidden dir: %q", got)
	case <-time.After(800 * time.Millisecond):
		// expected silence
	}
}

// TestWatchRoot_DoesNotEmitForFiles: a stray file at the root (e.g. a
// README or a README.draft.md) is not a project. The stat-based filter
// in loop() should drop it so the consumer doesn't waste a ScanOne walk.
func TestWatchRoot_DoesNotEmitForFiles(t *testing.T) {
	w, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	root := t.TempDir()
	if err := w.WatchRoot(root); err != nil {
		t.Fatal(err)
	}

	f := filepath.Join(root, "NOTES.md")
	if err := os.WriteFile(f, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-w.RootCreates:
		t.Errorf("unexpected RootCreates for file: %q", got)
	case <-time.After(800 * time.Millisecond):
		// expected: file creates don't fire the root-watch path
	}
}

// TestWatchRoot_Idempotent: calling WatchRoot twice for the same path
// returns nil without re-adding to fsnotify (which would return
// ErrEventOverflow on some platforms). Guards against a future refactor
// that moves the idempotency check out.
func TestWatchRoot_Idempotent(t *testing.T) {
	w, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	root := t.TempDir()
	if err := w.WatchRoot(root); err != nil {
		t.Fatal(err)
	}
	if err := w.WatchRoot(root); err != nil {
		t.Errorf("second WatchRoot should be no-op, got %v", err)
	}
}

// TestWatcher_LoopFiltersMatcher exercises the defensive event-loop
// filter: even if a directory was Add'd before a rule existed, a
// subsequent rule write suppresses the event at the loop boundary.
// Simulated here by Add'ing first with a tiny matcher that doesn't
// match, then externally rewriting the rules file.
func TestWatcher_LoopFiltersMatcher(t *testing.T) {
	dir := t.TempDir()

	rules := filepath.Join(t.TempDir(), "excludes")
	// Start with an unrelated rule so the file exists and matcher is
	// non-nil but the dir is currently allowed.
	if err := os.WriteFile(rules, []byte("/nonexistent-elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := excludes.Load(rules)
	if err != nil {
		t.Fatal(err)
	}

	w, err := New(nil, m)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	added, err := w.Add(dir)
	if err != nil || !added {
		t.Fatalf("Add(dir) initial: added=%v err=%v", added, err)
	}

	// Now a competing process (simulated) appends a rule covering dir.
	// Bump mtime explicitly so MaybeReload picks it up even on fast
	// filesystems where back-to-back writes share an mtime.
	if err := os.WriteFile(rules, []byte(dir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(rules, future, future); err != nil {
		t.Fatal(err)
	}

	// Write a PDMC file. The fsnotify event fires on a registered dir
	// (Add succeeded), but the loop's Matches() check drops it.
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-w.Events:
		t.Errorf("event should have been filtered by loop matcher, got %+v", ev)
	case <-time.After(1500 * time.Millisecond):
		// expected: silence (debounce(500ms) + margin)
	}
}
