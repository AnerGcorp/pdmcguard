// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hook generates shell hook snippets for zsh, bash, and fish.
package hook

import "fmt"

// ShellSnippet returns a shell hook script for the given shell.
// binPath is the absolute path to the pdmcguard binary.
// Supported shells: "zsh", "bash", "fish". Defaults to zsh.
func ShellSnippet(shell, binPath string) string {
	switch shell {
	case "bash":
		return fmt.Sprintf(`# PDMCGuard shell hook
__pdmcguard_precmd() { %s pre-check; }
PROMPT_COMMAND="__pdmcguard_precmd${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
`, binPath)
	case "fish":
		return fmt.Sprintf(`# PDMCGuard shell hook
function __pdmcguard_precmd --on-event fish_prompt
  %s pre-check
end
`, binPath)
	default:
		return fmt.Sprintf(`# PDMCGuard shell hook
__pdmcguard_precmd() { %s pre-check; }
precmd_functions+=(__pdmcguard_precmd)
`, binPath)
	}
}
