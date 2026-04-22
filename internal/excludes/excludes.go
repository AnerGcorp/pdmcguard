// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package excludes implements a path-based user-exclusion matcher that
// complements classifier.ExcludeStore. The inode store handles the "this
// filesystem object, whatever its path, is not a project" case; this
// matcher handles user-facing "this path or anything under it should be
// skipped" rules persisted to ~/.pdmcguard/excludes.
//
// Two rule kinds:
//
//   - absolute prefix (starts with "/", tilde expansion done at parse time):
//     matches the exact path or any descendant.
//   - basename token (no slashes): matches any path component equal to the
//     token, so "node_modules" catches every node_modules tree regardless
//     of parent.
//
// Hot reload: Matches stats the file on each call; if mtime changed since
// the last parse, rules are reloaded. This is what makes `pdmcguard
// exclude` visible to a running daemon without restart or IPC.
package excludes

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Defaults is consulted in addition to user rules. These complement (do
// not replace) classifier.Classify fingerprints — belt and suspenders for
// paths where the fingerprint file isn't present (e.g., a node_modules
// restored from tarball without .package-lock.json, or a build directory
// with no well-known marker file).
//
// Only basename tokens live here; prefix defaults would tie the code to
// specific user paths. If a user wants a prefix default they can add it
// to their excludes file.
var Defaults = []string{
	"node_modules",
	".yarn",
	".pnpm-store",
	"target",
	"dist",
	"build",
	".next",
	".nuxt",
	".venv",
	"venv",
	".tox",
	".cache",
	".gradle",
	"vendor",
}

// rule is either an absolute-path prefix (isPrefix=true, raw starts with
// "/") or a basename token (isPrefix=false, raw has no slashes).
type rule struct {
	raw      string
	isPrefix bool
}

// Matcher consults a user rules file plus built-in defaults to decide
// whether a directory should be skipped. Safe for concurrent use.
type Matcher struct {
	path string // absolute path to the rules file

	mu    sync.RWMutex
	mtime time.Time
	user  []rule
}

// Load reads the rules file at path and returns a ready-to-use Matcher.
// A missing file is not an error — the Matcher starts with just the
// built-in defaults, and the file is created on the first Add.
func Load(path string) (*Matcher, error) {
	m := &Matcher{path: path}
	if err := m.reload(); err != nil {
		return nil, err
	}
	return m, nil
}

// reload parses the rules file under write-lock. Missing file is fine —
// user rules are cleared to the empty slice.
func (m *Matcher) reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reloadLocked()
}

func (m *Matcher) reloadLocked() error {
	info, err := os.Stat(m.path)
	if os.IsNotExist(err) {
		m.user = nil
		m.mtime = time.Time{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", m.path, err)
	}

	f, err := os.Open(m.path)
	if err != nil {
		return fmt.Errorf("open %s: %w", m.path, err)
	}
	defer f.Close()

	var rules []rule
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if r, ok := parseRule(sc.Text()); ok {
			rules = append(rules, r)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", m.path, err)
	}

	m.user = rules
	m.mtime = info.ModTime()
	return nil
}

// parseRule normalizes a single line into a rule. Returns ok=false for
// blank / comment lines or invalid entries (which we skip silently).
// Tilde expansion is done here so stored rules stay user-writable but
// the runtime always compares absolute paths.
func parseRule(line string) (rule, bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return rule{}, false
	}

	// Tilde expansion: "~/foo" → "$HOME/foo"
	if strings.HasPrefix(s, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			s = filepath.Join(home, s[2:])
		}
	}

	if strings.HasPrefix(s, "/") {
		// Absolute prefix rule; clean to collapse ".." and trailing slash.
		return rule{raw: filepath.Clean(s), isPrefix: true}, true
	}

	// Basename token — reject entries with path separators; they're
	// ambiguous and we don't want to silently treat them as globs.
	if strings.ContainsRune(s, '/') {
		return rule{}, false
	}
	return rule{raw: s, isPrefix: false}, true
}

// MaybeReload stats the rules file and reloads if mtime advanced since
// the last parse. Cheap enough (a single stat) to call from hot paths;
// Matches calls it before every match.
func (m *Matcher) MaybeReload() {
	info, err := os.Stat(m.path)
	if os.IsNotExist(err) {
		m.mu.RLock()
		empty := len(m.user) == 0 && m.mtime.IsZero()
		m.mu.RUnlock()
		if !empty {
			_ = m.reload() // file was deleted; drop cached rules
		}
		return
	}
	if err != nil {
		return // transient stat error; keep cached rules
	}

	m.mu.RLock()
	same := info.ModTime().Equal(m.mtime)
	m.mu.RUnlock()
	if !same {
		_ = m.reload()
	}
}

// Matches reports whether absPath is covered by any user rule or default.
// Input should be an absolute, cleaned path; callers that have relative
// or symlink paths should normalize first.
func (m *Matcher) Matches(absPath string) bool {
	m.MaybeReload()

	m.mu.RLock()
	defer m.mu.RUnlock()

	// User rules first — in practice a user's explicit rule is more
	// selective than the broad defaults, so hitting it early is a minor
	// latency win. Correctness doesn't depend on order.
	for _, r := range m.user {
		if matchRule(r, absPath) {
			return true
		}
	}
	for _, name := range Defaults {
		if matchBasename(name, absPath) {
			return true
		}
	}
	return false
}

func matchRule(r rule, absPath string) bool {
	if r.isPrefix {
		return matchPrefix(r.raw, absPath)
	}
	return matchBasename(r.raw, absPath)
}

// matchPrefix matches exactly the rule path or any descendant. The
// trailing "/" guard prevents `/foo` from matching `/foobar`.
func matchPrefix(rule, absPath string) bool {
	if absPath == rule {
		return true
	}
	return strings.HasPrefix(absPath, rule+string(filepath.Separator))
}

// matchBasename returns true if any path component of absPath equals
// name. filepath.Separator split keeps us cross-platform even though
// we don't target Windows today.
func matchBasename(name, absPath string) bool {
	for _, part := range strings.Split(absPath, string(filepath.Separator)) {
		if part == name {
			return true
		}
	}
	return false
}

// Add appends a rule to the file (if not already present) and reparses.
// Raw is stored verbatim so users recognize what they typed in --list;
// tilde expansion happens at parse time on reload.
func (m *Matcher) Add(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("empty rule")
	}
	if _, ok := parseRule(raw); !ok {
		return fmt.Errorf("invalid rule %q (must be an absolute path or a basename with no slashes)", raw)
	}

	// Dedup against current user rules (defaults are implicit — adding a
	// default is allowed and harmless, but we don't re-add verbatim
	// duplicates).
	existing, err := readLines(m.path)
	if err != nil {
		return err
	}
	for _, line := range existing {
		if strings.TrimSpace(line) == raw {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}

	f, err := os.OpenFile(m.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", m.path, err)
	}
	if _, err := fmt.Fprintln(f, raw); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", m.path, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	return m.reload()
}

// Remove drops every line whose trimmed content equals raw, then
// reparses. Returns (false, nil) if no matching rule was found — the
// CLI uses this to distinguish "rule removed" from "rule wasn't there",
// so users typing the wrong thing get an explicit signal rather than
// silent success.
func (m *Matcher) Remove(raw string) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, fmt.Errorf("empty rule")
	}

	existing, err := readLines(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	kept := make([]string, 0, len(existing))
	changed := false
	for _, line := range existing {
		if strings.TrimSpace(line) == raw {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if !changed {
		return false, nil
	}

	out := strings.Join(kept, "\n")
	if len(kept) > 0 {
		out += "\n"
	}
	if err := os.WriteFile(m.path, []byte(out), 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", m.path, err)
	}
	if err := m.reload(); err != nil {
		return false, err
	}
	return true, nil
}

// UserRules returns the raw (pre-expansion) user rules in file order.
// Used by `pdmcguard exclude --list` so the user sees what they typed.
func (m *Matcher) UserRules() []string {
	m.MaybeReload()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.user))
	for i, r := range m.user {
		out[i] = r.raw
	}
	return out
}

// InspectResult summarizes the state of a rules file for `pdmcguard
// doctor`. Unlike Load, which silently drops unparseable lines so the
// daemon keeps running on a partially-broken file, Inspect surfaces the
// skipped lines by number so the user can see exactly which rules
// didn't land.
type InspectResult struct {
	// TotalLines is the number of newline-separated records in the file
	// (blank trailing line excluded).
	TotalLines int
	// ParsedRules is how many lines produced a usable rule.
	ParsedRules int
	// BlankOrComment counts lines that were intentionally skipped
	// (whitespace-only or starting with `#`). Those are not errors.
	BlankOrComment int
	// SkippedLines holds 1-based line numbers of lines that were neither
	// blank/comment nor parseable — e.g. `fixtures/legacy`, which
	// parseRule rejects because it's ambiguous. These are the ones the
	// user almost certainly meant as rules but that won't ever match.
	SkippedLines []int
}

// Inspect audits a rules file without mutating Matcher state. Returns a
// zero-value result and nil error if the file doesn't exist (a fresh
// install is healthy; there's just nothing to report). Returns an error
// only if the file is present but unreadable — that's the one case
// `doctor` treats as FAIL.
func Inspect(path string) (InspectResult, error) {
	var res InspectResult

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		res.TotalLines++
		trimmed := strings.TrimSpace(sc.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			res.BlankOrComment++
			continue
		}
		if _, ok := parseRule(sc.Text()); ok {
			res.ParsedRules++
			continue
		}
		res.SkippedLines = append(res.SkippedLines, lineNo)
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("read %s: %w", path, err)
	}
	return res, nil
}

// readLines returns the file's lines verbatim, or nil if the file
// doesn't exist. Used by Add/Remove to preserve comments and blank
// lines through edits.
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	// Strip trailing newline so we don't emit a spurious empty tail line.
	trimmed := strings.TrimRight(string(data), "\n")
	return strings.Split(trimmed, "\n"), nil
}
