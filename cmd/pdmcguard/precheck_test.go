// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnerGcorp/pdmcguard/internal/cache"
)

// fakeStore records calls to MarkShown so tests can assert the 24h quiet
// window is actually engaged when a banner prints.
type fakeStore struct {
	alerts    []cache.Alert
	markedFor []string
	closed    bool
}

func (f *fakeStore) CriticalAlerts(projectDir string) ([]cache.Alert, error) {
	return f.alerts, nil
}
func (f *fakeStore) MarkShown(projectDir string) error {
	f.markedFor = append(f.markedFor, projectDir)
	return nil
}
func (f *fakeStore) Close() error { f.closed = true; return nil }

// withProjectCwd sets up a temp directory containing a go.mod (so
// FindProjectDir matches it) and cd's into it for the duration of the test.
// Also overrides $HOME so the $HOME-bailout logic in FindProjectDir cannot
// accidentally abort the walk.
func withProjectCwd(t *testing.T) string {
	t.Helper()
	// Resolve symlinks up-front so the path we return matches what
	// os.Getwd() reports after Chdir — on macOS $TMPDIR lives under
	// /var/folders, which is a symlink to /private/var/folders.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "go.mod"), []byte("module x"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig, _ := os.Getwd()
	if err := os.Chdir(proj); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	return proj
}

// stubStore replaces openPreCheckStore with one returning the given fake for
// the duration of the test.
func stubStore(t *testing.T, f *fakeStore) {
	t.Helper()
	orig := openPreCheckStore
	openPreCheckStore = func() (preCheckStore, error) { return f, nil }
	t.Cleanup(func() { openPreCheckStore = orig })
}

// stubTTY forces stderrIsTTY to return v for the test's duration.
func stubTTY(t *testing.T, v bool) {
	t.Helper()
	orig := stderrIsTTY
	stderrIsTTY = func() bool { return v }
	t.Cleanup(func() { stderrIsTTY = orig })
}

// TestPreCheck_SilentWhenNonTTY guards the fix that stops the banner from
// leaking into CI logs and piped output. When stderr is not a TTY the
// function must produce no output and must NOT call MarkShown (otherwise
// piping `cd` output would silently start the quiet window).
func TestPreCheck_SilentWhenNonTTY(t *testing.T) {
	withProjectCwd(t)

	fake := &fakeStore{
		alerts: []cache.Alert{{AdvisoryID: "A", PackageName: "p", Severity: "critical"}},
	}
	stubStore(t, fake)
	stubTTY(t, false)

	var buf bytes.Buffer
	rc := runPreCheck(&buf)

	if rc != 0 {
		t.Errorf("expected rc=0 on non-TTY, got %d", rc)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output on non-TTY, got %q", buf.String())
	}
	if len(fake.markedFor) != 0 {
		t.Errorf("MarkShown must not fire on non-TTY, got %v", fake.markedFor)
	}
}

// TestPreCheck_CallsMarkShownAfterPrinting is the core regression test for
// the shell-spam fix. When there are alerts AND stderr is a TTY, the banner
// must print once AND MarkShown must be called to start the quiet window —
// otherwise the hook would reprint on the next directory change.
func TestPreCheck_CallsMarkShownAfterPrinting(t *testing.T) {
	proj := withProjectCwd(t)

	fake := &fakeStore{
		alerts: []cache.Alert{
			{AdvisoryID: "GHSA-1", PackageName: "litellm", Severity: "critical", Summary: "exposed"},
		},
	}
	stubStore(t, fake)
	stubTTY(t, true)

	var buf bytes.Buffer
	rc := runPreCheck(&buf)

	if rc != 1 {
		t.Errorf("expected rc=1 when alerts shown, got %d", rc)
	}
	if !strings.Contains(buf.String(), "litellm") {
		t.Errorf("expected banner to mention litellm, got %q", buf.String())
	}
	if len(fake.markedFor) != 1 || fake.markedFor[0] != proj {
		t.Errorf("expected MarkShown(%q) to be called exactly once, got %v", proj, fake.markedFor)
	}
}

// TestPreCheck_SilentWhenNoAlerts covers the zero-alerts path — no print,
// no MarkShown (there is nothing to suppress).
func TestPreCheck_SilentWhenNoAlerts(t *testing.T) {
	withProjectCwd(t)

	fake := &fakeStore{alerts: nil}
	stubStore(t, fake)
	stubTTY(t, true)

	var buf bytes.Buffer
	rc := runPreCheck(&buf)

	if rc != 0 {
		t.Errorf("expected rc=0 with no alerts, got %d", rc)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output with no alerts, got %q", buf.String())
	}
	if len(fake.markedFor) != 0 {
		t.Errorf("MarkShown should not fire when nothing was shown, got %v", fake.markedFor)
	}
}

// TestPreCheck_SilentOutsideProject covers `cd ~` with Bug D fixed: even if
// a stray package.json sits in $HOME, the banner must not print because
// FindProjectDir returns ErrNoProject.
func TestPreCheck_SilentOutsideProject(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	_ = os.WriteFile(filepath.Join(home, "package.json"), []byte("{}"), 0o644)

	orig, _ := os.Getwd()
	if err := os.Chdir(home); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	fake := &fakeStore{
		alerts: []cache.Alert{{AdvisoryID: "A", PackageName: "p", Severity: "critical"}},
	}
	stubStore(t, fake)
	stubTTY(t, true)

	var buf bytes.Buffer
	rc := runPreCheck(&buf)

	if rc != 0 {
		t.Errorf("expected rc=0 when cwd is $HOME, got %d", rc)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output when cwd is $HOME, got %q", buf.String())
	}
}
