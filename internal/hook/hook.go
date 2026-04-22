// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hook generates shell hook snippets for zsh, bash, and fish.
//
// The snippets intentionally do the MINIMUM amount of work per prompt:
//
//  1. bail if $PWD hasn't changed since the last run (directory-change hook
//     semantics, implemented by guard-variable or `chpwd`/`--on-variable PWD`),
//  2. bail if ~/.pdmcguard/alerts.flag does not exist (sentinel written by
//     the sync engine; absent when there are no critical alerts anywhere),
//  3. only then fork the pdmcguard binary to run pre-check.
//
// Together with the 24h quiet window enforced in the cache, this keeps
// prompt latency at zero in the common case and prevents the old
// every-keypress banner spam.
package hook

import "fmt"

// ShellSnippet returns a shell hook script for the given shell.
// binPath is the absolute path to the pdmcguard binary.
// Supported shells: "zsh", "bash", "fish". Defaults to zsh.
func ShellSnippet(shell, binPath string) string {
	switch shell {
	case "bash":
		return fmt.Sprintf(`# PDMCGuard shell hook
__pdmcguard_precmd() {
  [ "$PWD" = "$__pdmcguard_last_pwd" ] && return
  __pdmcguard_last_pwd="$PWD"
  [ -f "$HOME/.pdmcguard/alerts.flag" ] || return
  %s pre-check
}
case ";$PROMPT_COMMAND;" in
  *";__pdmcguard_precmd;"*) ;;
  *) PROMPT_COMMAND="__pdmcguard_precmd${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
`, binPath)
	case "fish":
		return fmt.Sprintf(`# PDMCGuard shell hook
function __pdmcguard_precmd --on-variable PWD
  test -f "$HOME/.pdmcguard/alerts.flag"; or return
  %s pre-check
end
`, binPath)
	default:
		return fmt.Sprintf(`# PDMCGuard shell hook
__pdmcguard_precmd() {
  [[ "$PWD" == "$__pdmcguard_last_pwd" ]] && return
  __pdmcguard_last_pwd="$PWD"
  [ -f "$HOME/.pdmcguard/alerts.flag" ] || return
  %s pre-check
}
if [[ -z ${chpwd_functions[(r)__pdmcguard_precmd]} ]]; then
  chpwd_functions+=(__pdmcguard_precmd)
fi
# Also fire once when the shell starts, in case we open a terminal directly in a project dir.
__pdmcguard_precmd
`, binPath)
	}
}
