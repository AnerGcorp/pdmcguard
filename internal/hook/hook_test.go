// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package hook

import (
	"strings"
	"testing"
)

const testBin = "/usr/local/bin/pdmcguard"

func TestShellSnippet_Zsh(t *testing.T) {
	s := ShellSnippet("zsh", testBin)

	// Must fire on directory change, NOT on every prompt — the old
	// `precmd_functions` wiring is what caused the ls/cd/Enter spam.
	if !strings.Contains(s, "chpwd_functions") {
		t.Error("zsh snippet should hook chpwd_functions (directory-change), not precmd_functions")
	}
	if strings.Contains(s, "precmd_functions+=") {
		t.Error("zsh snippet must NOT register with precmd_functions — that regresses the bug")
	}
	// Belt-and-suspenders $PWD guard.
	if !strings.Contains(s, `"$PWD" == "$__pdmcguard_last_pwd"`) {
		t.Error("zsh snippet should bail when $PWD has not changed")
	}
	// Zero-cost sentinel: stat() a flag before forking the Go binary.
	if !strings.Contains(s, "$HOME/.pdmcguard/alerts.flag") {
		t.Error("zsh snippet should check alerts.flag sentinel before forking")
	}
	if !strings.Contains(s, testBin+" pre-check") {
		t.Error("zsh snippet should call pdmcguard pre-check with full path")
	}
}

func TestShellSnippet_Bash(t *testing.T) {
	s := ShellSnippet("bash", testBin)

	if !strings.Contains(s, "PROMPT_COMMAND") {
		t.Error("bash snippet should use PROMPT_COMMAND")
	}
	if !strings.Contains(s, `"$PWD" = "$__pdmcguard_last_pwd"`) {
		t.Error("bash snippet should bail when $PWD has not changed")
	}
	if !strings.Contains(s, "$HOME/.pdmcguard/alerts.flag") {
		t.Error("bash snippet should check alerts.flag sentinel before forking")
	}
	if !strings.Contains(s, testBin+" pre-check") {
		t.Error("bash snippet should call pdmcguard pre-check with full path")
	}
}

func TestShellSnippet_Fish(t *testing.T) {
	s := ShellSnippet("fish", testBin)

	// Fish uses --on-variable PWD for the directory-change-only semantic.
	if !strings.Contains(s, "--on-variable PWD") {
		t.Error("fish snippet should use --on-variable PWD, not fish_prompt (which fires every prompt)")
	}
	if strings.Contains(s, "fish_prompt") {
		t.Error("fish snippet must NOT hook fish_prompt — that regresses the every-prompt bug")
	}
	if !strings.Contains(s, `test -f "$HOME/.pdmcguard/alerts.flag"`) {
		t.Error("fish snippet should check alerts.flag sentinel before forking")
	}
	if !strings.Contains(s, testBin+" pre-check") {
		t.Error("fish snippet should call pdmcguard pre-check with full path")
	}
}

func TestShellSnippet_DefaultsToZsh(t *testing.T) {
	s := ShellSnippet("unknown", testBin)
	if !strings.Contains(s, "chpwd_functions") {
		t.Error("unknown shell should default to zsh snippet (with chpwd_functions)")
	}
}

func TestShellSnippet_EmbedsBinPath(t *testing.T) {
	custom := "/opt/pdmcguard/bin/pdmcguard"
	s := ShellSnippet("zsh", custom)
	if !strings.Contains(s, custom) {
		t.Errorf("snippet should embed custom bin path %q", custom)
	}
}

// TestShellSnippet_BashIdempotent guards against the snippet being sourced
// twice (e.g. re-running `eval "$(pdmcguard hook-init)"`) — PROMPT_COMMAND
// should not accumulate duplicate __pdmcguard_precmd entries.
func TestShellSnippet_BashIdempotent(t *testing.T) {
	s := ShellSnippet("bash", testBin)
	if !strings.Contains(s, `*";__pdmcguard_precmd;"*`) {
		t.Error("bash snippet should dedup before appending to PROMPT_COMMAND")
	}
}
