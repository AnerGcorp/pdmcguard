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
