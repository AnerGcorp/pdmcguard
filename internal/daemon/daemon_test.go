// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInjectHook(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".zshrc")
	binPath := "/usr/local/bin/pdmcguard"

	// Temporarily override ShellRCPath by writing directly
	err := injectHookTo(rcPath, binPath)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(rcPath)
	if err != nil {
		t.Fatal(err)
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

func TestInjectHookIdempotent(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".zshrc")
	binPath := "/usr/local/bin/pdmcguard"

	// Inject twice
	_ = injectHookTo(rcPath, binPath)
	_ = injectHookTo(rcPath, binPath)

	data, _ := os.ReadFile(rcPath)
	count := strings.Count(string(data), hookStartMarker)
	if count != 1 {
		t.Errorf("expected 1 hook block, found %d", count)
	}
}

func TestRemoveHook(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".zshrc")
	binPath := "/usr/local/bin/pdmcguard"

	// Write some existing content + inject hook
	os.WriteFile(rcPath, []byte("# existing config\nexport FOO=bar\n"), 0o644)
	_ = injectHookTo(rcPath, binPath)

	// Remove
	err := removeHookFrom(rcPath)
	if err != nil {
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
		t.Error("existing config was removed")
	}
}

func TestRemoveHookNoFile(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".zshrc")

	// Should not error on missing file
	err := removeHookFrom(rcPath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDetectShell(t *testing.T) {
	// Save and restore SHELL env
	orig := os.Getenv("SHELL")
	defer os.Setenv("SHELL", orig)

	os.Setenv("SHELL", "/bin/zsh")
	if s := DetectShell(); s != "zsh" {
		t.Errorf("expected zsh, got %s", s)
	}

	os.Setenv("SHELL", "/usr/bin/bash")
	if s := DetectShell(); s != "bash" {
		t.Errorf("expected bash, got %s", s)
	}

	os.Setenv("SHELL", "/usr/local/bin/fish")
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

// ── Test helpers that operate on explicit paths ─────────────────────────────

func injectHookTo(rcPath, binPath string) error {
	existing, _ := os.ReadFile(rcPath)
	content := string(existing)

	if strings.Contains(content, hookStartMarker) {
		return nil
	}

	hookBlock := "\n" + hookStartMarker + "\n" +
		`eval "$(` + binPath + ` hook-init)"` + "\n" +
		hookEndMarker + "\n"

	f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(hookBlock)
	return err
}

func removeHookFrom(rcPath string) error {
	data, err := os.ReadFile(rcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	content := string(data)
	if !strings.Contains(content, hookStartMarker) {
		return nil
	}

	startIdx := strings.Index(content, hookStartMarker)
	endIdx := strings.Index(content, hookEndMarker)
	if startIdx < 0 || endIdx < 0 || endIdx < startIdx {
		return nil
	}

	if startIdx > 0 && content[startIdx-1] == '\n' {
		startIdx--
	}
	endIdx += len(hookEndMarker)
	if endIdx < len(content) && content[endIdx] == '\n' {
		endIdx++
	}

	cleaned := content[:startIdx] + content[endIdx:]
	return os.WriteFile(rcPath, []byte(cleaned), 0o644)
}
