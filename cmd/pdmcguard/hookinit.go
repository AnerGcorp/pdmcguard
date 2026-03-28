// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AnerGcorp/pdmcguard/internal/hook"
)

// cmdHookInit outputs a shell hook snippet to stdout.
// Usage: eval "$(pdmcguard hook-init)"
func cmdHookInit(args []string) {
	shell := detectShell(args)

	binPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdmcguard: cannot resolve executable path: %v\n", err)
		os.Exit(1)
	}
	binPath, _ = filepath.EvalSymlinks(binPath)

	fmt.Print(hook.ShellSnippet(shell, binPath))
}

func detectShell(args []string) string {
	for i, a := range args {
		if a == "--shell" && i+1 < len(args) {
			return args[i+1]
		}
	}
	if sh := os.Getenv("SHELL"); sh != "" {
		return filepath.Base(sh)
	}
	return "zsh"
}
