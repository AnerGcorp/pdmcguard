// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config provides paths and configuration for the PDMCGuard daemon.
package config

import (
	"os"
	"path/filepath"
)

const dirName = ".pdmcguard"

// Dir returns the path to the PDMCGuard configuration directory (~/.pdmcguard).
// Creates the directory if it does not exist.
func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, dirName)
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// FilePath returns the full path to a file inside the config directory.
func FilePath(name string) string {
	return filepath.Join(Dir(), name)
}
