// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	hookStartMarker = "# pdmcguard:start"
	hookEndMarker   = "# pdmcguard:end"
)

// ShellRCPath returns the rc file path for the given shell.
func ShellRCPath(shell string) string {
	home, _ := os.UserHomeDir()
	switch shell {
	case "bash":
		return filepath.Join(home, ".bashrc")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	default: // zsh
		return filepath.Join(home, ".zshrc")
	}
}

// DetectShell returns the current user's shell name (zsh, bash, fish).
func DetectShell() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		return filepath.Base(sh)
	}
	return "zsh"
}

// InjectHook appends the PDMCGuard shell hook to the user's rc file.
// Uses markers for clean removal. Skips if already present.
func InjectHook(shell, binPath string) error {
	rcPath := ShellRCPath(shell)

	// Read existing content (or empty if file doesn't exist)
	existing, _ := os.ReadFile(rcPath)
	content := string(existing)

	// Already injected?
	if strings.Contains(content, hookStartMarker) {
		return nil
	}

	hookBlock := fmt.Sprintf(`
%s
eval "$(%s hook-init)"
%s
`, hookStartMarker, binPath, hookEndMarker)

	// Ensure parent dir exists (fish config dir may not)
	if err := os.MkdirAll(filepath.Dir(rcPath), 0o755); err != nil {
		return fmt.Errorf("create rc dir: %w", err)
	}

	f, err := os.OpenFile(rcPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", rcPath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(hookBlock); err != nil {
		return fmt.Errorf("write hook: %w", err)
	}

	return nil
}

// RemoveHook removes the PDMCGuard shell hook from the user's rc file.
func RemoveHook(shell string) error {
	rcPath := ShellRCPath(shell)

	data, err := os.ReadFile(rcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	content := string(data)
	if !strings.Contains(content, hookStartMarker) {
		return nil // Nothing to remove
	}

	// Remove everything between start and end markers (inclusive)
	startIdx := strings.Index(content, hookStartMarker)
	endIdx := strings.Index(content, hookEndMarker)
	if startIdx < 0 || endIdx < 0 || endIdx < startIdx {
		return nil
	}

	// Include the newline before the start marker and after the end marker
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
