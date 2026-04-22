// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package excludes

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newMatcher(t *testing.T) (*Matcher, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "excludes")
	m, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return m, path
}

// TestLoad_MissingFileIsOK ensures Load doesn't error when the rules
// file doesn't exist yet — the daemon starts fine on a clean machine
// and the file is created lazily on first Add.
func TestLoad_MissingFileIsOK(t *testing.T) {
	m, path := newMatcher(t)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected missing file, got err=%v", err)
	}
	// Defaults still apply even with no file.
	if !m.Matches("/tmp/project/node_modules") {
		t.Error("default node_modules should match on empty matcher")
	}
}

// TestDefaults_MatchAsBasenames verifies every default is treated as a
// basename token (any path component match, not just leaf).
func TestDefaults_MatchAsBasenames(t *testing.T) {
	m, _ := newMatcher(t)
	cases := []struct {
		path string
		want bool
	}{
		{"/a/b/node_modules", true},
		{"/a/b/node_modules/foo/bar", true},
		{"/a/b/target", true},
		{"/a/b/dist/chunk.js", true},
		{"/a/b/regular-project", false},
		{"/a/b/node_modules_fake", false}, // exact component match, not substring
	}
	for _, tc := range cases {
		if got := m.Matches(tc.path); got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestAdd_PrefixRule exercises the absolute-path prefix branch: the
// rule should cover the exact path and any descendant, but not a
// prefix-collision sibling ("/foo" must not match "/foobar").
func TestAdd_PrefixRule(t *testing.T) {
	m, _ := newMatcher(t)
	if err := m.Add("/home/user/monorepo/legacy"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	cases := []struct {
		path string
		want bool
	}{
		{"/home/user/monorepo/legacy", true},
		{"/home/user/monorepo/legacy/sub/pkg", true},
		{"/home/user/monorepo/legacy-ui", false}, // sibling, not descendant
		{"/home/user/monorepo/modern", false},
	}
	for _, tc := range cases {
		if got := m.Matches(tc.path); got != tc.want {
			t.Errorf("Matches(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestAdd_BasenameRule: user-added basename behaves the same as
// defaults do, anywhere in the tree.
func TestAdd_BasenameRule(t *testing.T) {
	m, _ := newMatcher(t)
	if err := m.Add("fixtures"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !m.Matches("/a/b/fixtures/x") {
		t.Error("basename rule should match descendant")
	}
	if m.Matches("/a/b/real-project") {
		t.Error("basename rule should not match unrelated paths")
	}
}

// TestAdd_RejectsSlashInBasename: "fixtures/legacy" is ambiguous — not
// a valid basename, not an absolute prefix. Reject rather than silently
// treating it as a glob.
func TestAdd_RejectsInvalid(t *testing.T) {
	m, _ := newMatcher(t)
	if err := m.Add("fixtures/legacy"); err == nil {
		t.Error("expected error for non-absolute path containing slash")
	}
	if err := m.Add(""); err == nil {
		t.Error("expected error for empty rule")
	}
}

// TestAdd_Dedup: adding the same rule twice doesn't duplicate a line
// in the file. Exercises the read-and-dedup branch in Add.
func TestAdd_Dedup(t *testing.T) {
	m, path := newMatcher(t)
	if err := m.Add("node_modules"); err != nil {
		t.Fatalf("Add #1: %v", err)
	}
	if err := m.Add("node_modules"); err != nil {
		t.Fatalf("Add #2: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "node_modules\n" {
		t.Errorf("expected single line, got %q", string(data))
	}
}

// TestRemove: dropping a rule removes it from the file and the
// in-memory set. Remaining user rules + defaults still match.
func TestRemove(t *testing.T) {
	m, _ := newMatcher(t)
	if err := m.Add("/home/user/monorepo/legacy"); err != nil {
		t.Fatal(err)
	}
	if err := m.Add("fixtures"); err != nil {
		t.Fatal(err)
	}

	removed, err := m.Remove("fixtures")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !removed {
		t.Error("Remove should report changed=true for existing rule")
	}
	if m.Matches("/anywhere/fixtures/x") {
		t.Error("removed basename rule should no longer match")
	}
	if !m.Matches("/home/user/monorepo/legacy/sub") {
		t.Error("other rule should still match after Remove")
	}
	// Defaults intact.
	if !m.Matches("/a/node_modules") {
		t.Error("defaults should survive Remove")
	}

	// Removing again is a no-op that reports false (for the CLI to
	// turn into a user-visible "no such rule" error).
	removed, err = m.Remove("fixtures")
	if err != nil {
		t.Fatalf("Remove second time: %v", err)
	}
	if removed {
		t.Error("Remove of absent rule should report changed=false")
	}

	// Removing a rule that never existed also reports false.
	removed, err = m.Remove("never-added")
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Error("Remove of unknown rule should report changed=false")
	}
}

// TestMaybeReload_PicksUpExternalEdit is the headline hot-reload
// regression test: a file written outside the Matcher (simulating a
// second process running `pdmcguard exclude`) is picked up by the
// running daemon's next Matches call.
func TestMaybeReload_PicksUpExternalEdit(t *testing.T) {
	m, path := newMatcher(t)

	// Initial state: nothing matches /tmp/foo/bar
	if m.Matches("/tmp/foo/bar") {
		t.Fatal("pre-state: should not match")
	}

	// Simulate another process writing a rule. Must bump mtime past
	// the Matcher's cached mtime; forcibly set the file's mtime to
	// "now + 1s" so the test isn't flaky on fast filesystems.
	if err := os.WriteFile(path, []byte("/tmp/foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	if !m.Matches("/tmp/foo/bar") {
		t.Error("externally-added rule not picked up by MaybeReload")
	}
}

// TestParseRule_CommentsAndBlanks ensures the file format tolerates
// user annotations.
func TestParseRule_CommentsAndBlanks(t *testing.T) {
	m, path := newMatcher(t)
	content := `# managed by pdmcguard

# Exclude the legacy monorepo
/home/user/monorepo/legacy

fixtures
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Second)
	os.Chtimes(path, future, future)

	if !m.Matches("/home/user/monorepo/legacy/sub") {
		t.Error("prefix rule from file not active")
	}
	if !m.Matches("/x/fixtures/y") {
		t.Error("basename rule from file not active")
	}
	rules := m.UserRules()
	if len(rules) != 2 {
		t.Errorf("UserRules len = %d, want 2 (got %v)", len(rules), rules)
	}
}

// TestInspect_FlagsInvalidLines is the headline guard for the helper
// backing `pdmcguard doctor`: a file with a mix of comments, blanks,
// real rules, and one silently-rejected line should report each
// category distinctly and surface the skipped line's 1-based number.
func TestInspect_FlagsInvalidLines(t *testing.T) {
	_, path := newMatcher(t)
	content := `# managed by pdmcguard

/home/user/monorepo/legacy
fixtures
fixtures/legacy
# trailing comment
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	// 6 content lines in the file (the trailing newline doesn't add one).
	if res.TotalLines != 6 {
		t.Errorf("TotalLines = %d, want 6", res.TotalLines)
	}
	if res.ParsedRules != 2 {
		t.Errorf("ParsedRules = %d, want 2", res.ParsedRules)
	}
	// 1 leading `# managed`, 1 blank line 2, 1 trailing `# trailing comment`.
	if res.BlankOrComment != 3 {
		t.Errorf("BlankOrComment = %d, want 3", res.BlankOrComment)
	}
	// `fixtures/legacy` is on line 5.
	if len(res.SkippedLines) != 1 || res.SkippedLines[0] != 5 {
		t.Errorf("SkippedLines = %v, want [5]", res.SkippedLines)
	}
}

// TestInspect_MissingFileIsClean ensures Inspect returns a zero result
// (not an error) when the rules file doesn't exist — a fresh install
// should report as healthy, not broken.
func TestInspect_MissingFileIsClean(t *testing.T) {
	_, path := newMatcher(t)
	res, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect on missing file: %v", err)
	}
	if res.TotalLines != 0 || res.ParsedRules != 0 || len(res.SkippedLines) != 0 {
		t.Errorf("missing file should produce zero result, got %+v", res)
	}
}

// TestTildeExpansion: "~/foo" in the file is expanded against
// $HOME at parse time so match comparisons use absolute paths.
func TestTildeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	m, _ := newMatcher(t)
	if err := m.Add("~/monorepo/legacy"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "monorepo", "legacy", "pkg")
	if !m.Matches(target) {
		t.Errorf("tilde-expanded rule should match %q", target)
	}
}
