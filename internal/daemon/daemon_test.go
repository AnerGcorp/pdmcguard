// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withFakeHome redirects $HOME to a temp dir so ShellRCPath (and thus the
// real InjectHook/RemoveHook) operate inside the sandbox. Returns the path
// that ShellRCPath(shell) resolves to under the fake home.
func withFakeHome(t *testing.T, shell string) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return ShellRCPath(shell)
}

// TestInjectHook exercises the real InjectHook on a redirected $HOME instead
// of duplicating its body in a test helper. Previously the test wrote via a
// copy-paste `injectHookTo` function, which meant bugs in the real InjectHook
// could never be caught.
func TestInjectHook(t *testing.T) {
	rcPath := withFakeHome(t, "zsh")
	binPath := "/usr/local/bin/pdmcguard"

	if err := InjectHook("zsh", binPath); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatalf("rc not written: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, hookStartMarker) {
		t.Error("missing start marker")
	}
	if !strings.Contains(content, hookEndMarker) {
		t.Error("missing end marker")
	}
	if !strings.Contains(content, binPath) {
		t.Error("missing bin path in hook")
	}
	if !strings.Contains(content, "hook-init") {
		t.Error("missing hook-init command")
	}
}

// TestInjectHookIdempotent guards against sourcing-twice accidentally
// appending two hook blocks to the rc file.
func TestInjectHookIdempotent(t *testing.T) {
	rcPath := withFakeHome(t, "zsh")
	binPath := "/usr/local/bin/pdmcguard"

	if err := InjectHook("zsh", binPath); err != nil {
		t.Fatal(err)
	}
	if err := InjectHook("zsh", binPath); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(rcPath)
	count := strings.Count(string(data), hookStartMarker)
	if count != 1 {
		t.Errorf("expected 1 hook block, found %d", count)
	}
}

// TestInjectHookFishCreatesConfigDir covers the fish path where
// ~/.config/fish/ does not exist yet — InjectHook must MkdirAll.
func TestInjectHookFishCreatesConfigDir(t *testing.T) {
	rcPath := withFakeHome(t, "fish")
	if _, err := os.Stat(filepath.Dir(rcPath)); !os.IsNotExist(err) {
		t.Fatalf("expected fish config dir to be absent initially, got err=%v", err)
	}

	if err := InjectHook("fish", "/usr/local/bin/pdmcguard"); err != nil {
		t.Fatalf("InjectHook(fish) should create parent dirs, got %v", err)
	}

	data, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatalf("fish config not written: %v", err)
	}
	if !strings.Contains(string(data), hookStartMarker) {
		t.Error("fish config missing start marker")
	}
}

// TestRemoveHook drives the real RemoveHook and asserts the user's existing
// config is preserved intact while the marked block disappears.
func TestRemoveHook(t *testing.T) {
	rcPath := withFakeHome(t, "zsh")
	binPath := "/usr/local/bin/pdmcguard"

	// User already had config in their .zshrc before PDMCGuard touched it.
	if err := os.WriteFile(rcPath, []byte("# existing config\nexport FOO=bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InjectHook("zsh", binPath); err != nil {
		t.Fatal(err)
	}

	if err := RemoveHook("zsh"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(rcPath)
	content := string(data)

	if strings.Contains(content, hookStartMarker) {
		t.Error("start marker still present after removal")
	}
	if strings.Contains(content, "pdmcguard") {
		t.Error("pdmcguard still present after removal")
	}
	if !strings.Contains(content, "export FOO=bar") {
		t.Error("existing config was removed — RemoveHook must not touch user content")
	}
}

// TestRemoveHookNoFile ensures calling RemoveHook on a brand-new $HOME (no
// rc file at all) is not an error — install → uninstall must work even if
// the user never opened their shell in between.
func TestRemoveHookNoFile(t *testing.T) {
	withFakeHome(t, "zsh")

	if err := RemoveHook("zsh"); err != nil {
		t.Fatal(err)
	}
}

// lifecycleRoundTrip is the shared assertion body for the per-shell
// lifecycle tests. Guards the uninstall path: Stage 1 rewrote the shell
// snippets but left hookStartMarker/hookEndMarker unchanged, so RemoveHook
// should still find and strip cleanly — prove it per shell rather than
// trust that the markers are enough.
func lifecycleRoundTrip(t *testing.T, shell string) {
	t.Helper()
	rcPath := withFakeHome(t, shell)
	binPath := "/fake/bin/pdmcguard"

	if err := InjectHook(shell, binPath); err != nil {
		t.Fatalf("InjectHook(%s): %v", shell, err)
	}

	data, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatalf("rc not written for %s: %v", shell, err)
	}
	content := string(data)

	for _, want := range []string{hookStartMarker, hookEndMarker, binPath, "hook-init"} {
		if !strings.Contains(content, want) {
			t.Errorf("%s rc missing %q after InjectHook", shell, want)
		}
	}

	if err := RemoveHook(shell); err != nil {
		t.Fatalf("RemoveHook(%s): %v", shell, err)
	}

	// File may or may not still exist depending on shell (fish writes a
	// nested config dir). Either way, no trace of pdmcguard should remain.
	after, err := os.ReadFile(rcPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read after remove (%s): %v", shell, err)
	}
	if strings.Contains(strings.ToLower(string(after)), "pdmcguard") {
		t.Errorf("%s rc still contains pdmcguard reference after RemoveHook:\n%s", shell, after)
	}
}

func TestShellHookLifecycle_Zsh(t *testing.T)  { lifecycleRoundTrip(t, "zsh") }
func TestShellHookLifecycle_Bash(t *testing.T) { lifecycleRoundTrip(t, "bash") }
func TestShellHookLifecycle_Fish(t *testing.T) { lifecycleRoundTrip(t, "fish") }

// TestShellHookLifecycle_PreservesUserContent exercises the full
// inject → remove cycle against a pre-populated rc file. Distinct from
// TestRemoveHook (which seeds before injecting but only one shell): here
// we guarantee that arbitrary surrounding content — including content
// both before AND after the hook block — is preserved byte-identical
// across the cycle for the default (zsh) path.
func TestShellHookLifecycle_PreservesUserContent(t *testing.T) {
	rcPath := withFakeHome(t, "zsh")
	original := "# my zshrc\nexport FOO=bar\n\n# after\nalias g=git\n"
	if err := os.WriteFile(rcPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := InjectHook("zsh", "/fake/bin/pdmcguard"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveHook("zsh"); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatal(err)
	}
	// Remove may leave at most a trailing newline diff; normalize both.
	if strings.TrimRight(string(got), "\n") != strings.TrimRight(original, "\n") {
		t.Errorf("user content mutated by inject+remove cycle\nwant:\n%q\ngot:\n%q", original, string(got))
	}
}

// TestInjectHook_AddsPathExport is the headline guarantee of the
// install-PATH-gap fix: the block InjectHook writes MUST put the binary's
// directory on $PATH so `pdmcguard <subcommand>` resolves to the installed
// binary rather than a stale global or "command not found".
func TestInjectHook_AddsPathExport(t *testing.T) {
	rcPath := withFakeHome(t, "zsh")
	binPath := "/opt/pdmcguard/bin/pdmcguard"

	if err := InjectHook("zsh", binPath); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(rcPath)
	content := string(data)

	wantPath := `export PATH="/opt/pdmcguard/bin:$PATH"`
	if !strings.Contains(content, wantPath) {
		t.Errorf("expected PATH export %q, got:\n%s", wantPath, content)
	}
	// PATH line must come before the eval so the eval can resolve
	// pdmcguard subcommands if they're referenced from hook-init output.
	pathIdx := strings.Index(content, wantPath)
	evalIdx := strings.Index(content, "eval \"$(")
	if pathIdx < 0 || evalIdx < 0 || pathIdx > evalIdx {
		t.Errorf("PATH export must precede eval line (pathIdx=%d, evalIdx=%d)", pathIdx, evalIdx)
	}
}

// TestInjectHook_ReinstallUpgradesOldBlock is the v0.3.0 → v0.3.1 upgrade
// regression test. Existing users have a no-PATH block in their rc file;
// a plain reinstall used to short-circuit on "markers already present"
// and silently leave them stuck. The fix rewrites the block every time,
// so the PATH line lands on the next `pdmcguard install`.
func TestInjectHook_ReinstallUpgradesOldBlock(t *testing.T) {
	rcPath := withFakeHome(t, "zsh")
	binPath := "/fake/bin/pdmcguard"

	// Seed the rc with the pre-fix block format (no PATH line) plus
	// surrounding user content that must survive the upgrade.
	oldBlock := "\n" + hookStartMarker + "\n" +
		"eval \"$(" + binPath + " hook-init)\"\n" +
		hookEndMarker + "\n"
	seeded := "# my zshrc\nexport FOO=bar\n" + oldBlock + "alias g=git\n"
	if err := os.WriteFile(rcPath, []byte(seeded), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := InjectHook("zsh", binPath); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(rcPath)
	content := string(data)

	// Exactly one block — no duplicate from the reinstall.
	if got := strings.Count(content, hookStartMarker); got != 1 {
		t.Errorf("expected 1 block after reinstall, got %d:\n%s", got, content)
	}
	// The new PATH line is present.
	if !strings.Contains(content, `export PATH="/fake/bin:$PATH"`) {
		t.Errorf("reinstall did not add PATH line; content:\n%s", content)
	}
	// Surrounding user content survived.
	if !strings.Contains(content, "export FOO=bar") {
		t.Error("pre-block user content lost on reinstall")
	}
	if !strings.Contains(content, "alias g=git") {
		t.Error("post-block user content lost on reinstall")
	}
}

// TestInjectHook_FishUsesSetGx covers fish's non-POSIX PATH syntax. fish
// doesn't have `export`, so the block must use `set -gx PATH "..." $PATH`
// instead or the rc file fails to parse on the user's next shell start.
func TestInjectHook_FishUsesSetGx(t *testing.T) {
	rcPath := withFakeHome(t, "fish")

	if err := InjectHook("fish", "/fake/bin/pdmcguard"); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(rcPath)
	content := string(data)

	wantPath := `set -gx PATH "/fake/bin" $PATH`
	if !strings.Contains(content, wantPath) {
		t.Errorf("expected fish PATH line %q, got:\n%s", wantPath, content)
	}
	if strings.Contains(content, "export PATH=") {
		t.Error("fish block must not use bash/zsh 'export PATH=' syntax")
	}
}

// TestInjectHook_PreservesSurroundingOnReinject is distinct from the full
// lifecycle test: it verifies content preservation across a reinject
// (strip + rewrite) without ever calling RemoveHook. This is the hot path
// for every `pdmcguard install` from here on.
func TestInjectHook_PreservesSurroundingOnReinject(t *testing.T) {
	rcPath := withFakeHome(t, "zsh")
	binPath := "/fake/bin/pdmcguard"

	// First inject on a pre-populated rc.
	seeded := "alias ll=\"ls -la\"\nexport FOO=bar\n"
	if err := os.WriteFile(rcPath, []byte(seeded), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InjectHook("zsh", binPath); err != nil {
		t.Fatal(err)
	}

	// Append more user content AFTER the block (simulating a user editing
	// their rc between installs) and re-inject.
	data, _ := os.ReadFile(rcPath)
	trailing := "\nexport BAZ=qux\n"
	if err := os.WriteFile(rcPath, append(data, []byte(trailing)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InjectHook("zsh", binPath); err != nil {
		t.Fatal(err)
	}

	final, _ := os.ReadFile(rcPath)
	content := string(final)

	for _, want := range []string{"alias ll=\"ls -la\"", "export FOO=bar", "export BAZ=qux"} {
		if !strings.Contains(content, want) {
			t.Errorf("reinject lost surrounding content %q; got:\n%s", want, content)
		}
	}
	if got := strings.Count(content, hookStartMarker); got != 1 {
		t.Errorf("expected 1 block, got %d", got)
	}
}

func TestDetectShell(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	if s := DetectShell(); s != "zsh" {
		t.Errorf("expected zsh, got %s", s)
	}

	t.Setenv("SHELL", "/usr/bin/bash")
	if s := DetectShell(); s != "bash" {
		t.Errorf("expected bash, got %s", s)
	}

	t.Setenv("SHELL", "/usr/local/bin/fish")
	if s := DetectShell(); s != "fish" {
		t.Errorf("expected fish, got %s", s)
	}
}

func TestShellRCPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		shell    string
		contains string
	}{
		{"zsh", ".zshrc"},
		{"bash", ".bashrc"},
		{"fish", "config.fish"},
	}

	for _, tt := range tests {
		path := ShellRCPath(tt.shell)
		if !strings.HasPrefix(path, home) {
			t.Errorf("ShellRCPath(%s) = %q, not under home", tt.shell, path)
		}
		if !strings.Contains(path, tt.contains) {
			t.Errorf("ShellRCPath(%s) = %q, missing %s", tt.shell, path, tt.contains)
		}
	}
}
