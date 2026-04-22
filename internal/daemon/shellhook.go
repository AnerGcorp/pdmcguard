// PDMCGuard — Passive Dependency Monitor & Compromise Guard
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

// InjectHook writes (or rewrites) the PDMCGuard shell-hook block inside the
// user's rc file. The block is delimited by the hookStartMarker /
// hookEndMarker pair and contains:
//
//   - a shell-specific PATH export so `pdmcguard <subcommand>` resolves to
//     the binary we just installed (without this, a user whose $PATH has no
//     entry for ~/.pdmcguard/bin gets "command not found" or worse, a stale
//     binary from an earlier install);
//   - the `eval "$(... hook-init)"` line that wires the pre-prompt check.
//
// Reinstall semantics: any prior block is stripped first, then a fresh one
// is appended. This makes `pdmcguard install` idempotent and — crucially —
// an upgrade vector: a v0.3.0 user running the v0.3.1 installer gets the
// new PATH line instead of silently retaining the old block.
func InjectHook(shell, binPath string) error {
	rcPath := ShellRCPath(shell)

	existing, _ := os.ReadFile(rcPath)
	cleaned := stripHookBlock(string(existing))

	block := buildHookBlock(shell, binPath)

	// Ensure parent dir exists (fish config dir may not).
	if err := os.MkdirAll(filepath.Dir(rcPath), 0o755); err != nil {
		return fmt.Errorf("create rc dir: %w", err)
	}

	if err := os.WriteFile(rcPath, []byte(cleaned+block), 0o644); err != nil {
		return fmt.Errorf("write hook: %w", err)
	}
	return nil
}

// RemoveHook removes the PDMCGuard shell-hook block from the user's rc
// file. No-op if the markers aren't present or the file doesn't exist.
func RemoveHook(shell string) error {
	rcPath := ShellRCPath(shell)

	data, err := os.ReadFile(rcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return os.WriteFile(rcPath, []byte(stripHookBlock(string(data))), 0o644)
}

// stripHookBlock returns content with any content between the start/end
// markers (inclusive, plus the surrounding newlines) removed. If the
// markers aren't present or are malformed (end before start) the input is
// returned unchanged — callers treat that as a no-op.
//
// Substring-based on purpose: the block can legitimately grow over time
// (PATH line, eval line, future additions) and anything the installer
// itself wrote between the markers is fair game to strip. A user who
// hand-edited the block also gets a clean slate on reinstall, which is
// preferable to a silent "skip if present" short-circuit that leaves them
// on a stale block forever.
func stripHookBlock(content string) string {
	if !strings.Contains(content, hookStartMarker) {
		return content
	}
	startIdx := strings.Index(content, hookStartMarker)
	endIdx := strings.Index(content, hookEndMarker)
	if startIdx < 0 || endIdx < 0 || endIdx < startIdx {
		return content
	}

	// Include the newline before the start marker and after the end marker
	// so stripping doesn't leave an empty line where the block used to be.
	if startIdx > 0 && content[startIdx-1] == '\n' {
		startIdx--
	}
	endIdx += len(hookEndMarker)
	if endIdx < len(content) && content[endIdx] == '\n' {
		endIdx++
	}
	return content[:startIdx] + content[endIdx:]
}

// buildHookBlock assembles the shell-hook block for the given shell. The
// PATH line uses absolute paths (no $HOME / ~ expansion) for
// shell-consistency; the directory is derived from binPath so installer
// and block always agree on location. Fish doesn't have `export`, so that
// case gets its own syntax.
func buildHookBlock(shell, binPath string) string {
	binDir := filepath.Dir(binPath)

	var pathLine string
	if shell == "fish" {
		pathLine = fmt.Sprintf(`set -gx PATH "%s" $PATH`, binDir)
	} else {
		pathLine = fmt.Sprintf(`export PATH="%s:$PATH"`, binDir)
	}

	return fmt.Sprintf("\n%s\n%s\neval \"$(%s hook-init)\"\n%s\n",
		hookStartMarker, pathLine, binPath, hookEndMarker)
}
