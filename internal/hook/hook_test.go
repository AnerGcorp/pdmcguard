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
	if !strings.Contains(s, "precmd_functions") {
		t.Error("zsh snippet should contain precmd_functions")
	}
	if !strings.Contains(s, testBin+" pre-check") {
		t.Error("zsh snippet should call pdmcguard pre-check with full path")
	}
}

func TestShellSnippet_Bash(t *testing.T) {
	s := ShellSnippet("bash", testBin)
	if !strings.Contains(s, "PROMPT_COMMAND") {
		t.Error("bash snippet should contain PROMPT_COMMAND")
	}
	if !strings.Contains(s, testBin+" pre-check") {
		t.Error("bash snippet should call pdmcguard pre-check with full path")
	}
}

func TestShellSnippet_Fish(t *testing.T) {
	s := ShellSnippet("fish", testBin)
	if !strings.Contains(s, "fish_prompt") {
		t.Error("fish snippet should contain fish_prompt")
	}
	if !strings.Contains(s, testBin+" pre-check") {
		t.Error("fish snippet should call pdmcguard pre-check with full path")
	}
}

func TestShellSnippet_DefaultsToZsh(t *testing.T) {
	s := ShellSnippet("unknown", testBin)
	if !strings.Contains(s, "precmd_functions") {
		t.Error("unknown shell should default to zsh snippet")
	}
}

func TestShellSnippet_EmbedsBinPath(t *testing.T) {
	custom := "/opt/pdmcguard/bin/pdmcguard"
	s := ShellSnippet("zsh", custom)
	if !strings.Contains(s, custom) {
		t.Errorf("snippet should embed custom bin path %q", custom)
	}
}
