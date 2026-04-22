// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package hook

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/AnerGcorp/pdmcguard/internal/watcher"
)

// ErrNoProject is returned when no project directory is found.
var ErrNoProject = errors.New("no project directory found")

const maxDepth = 50

// FindProjectDir walks upward from startDir looking for a directory that
// contains at least one PDMC file (package.json, go.mod, etc.).
// Returns the first matching directory or ErrNoProject.
//
// The walk stops at $HOME (if set and non-empty). Without this boundary, a
// stray lockfile left in the user's home directory — a common accident
// (npm global install, dotfile repo, an old download) — causes every
// freshly-opened terminal to match $HOME as "the project" and spam the
// shell-hook banner before the user has even cd'd anywhere.
func FindProjectDir(startDir string) (string, error) {
	home := os.Getenv("HOME")
	dir := startDir
	for i := 0; i < maxDepth; i++ {
		// Do not treat $HOME itself as a project. Stray lockfiles sitting
		// directly in home (npm global, downloads, dotfile repos) would
		// otherwise match for every subdir of $HOME and spam every shell.
		if home != "" && dir == home {
			break
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		for _, e := range entries {
			if !e.IsDir() && watcher.IsPDMC(e.Name()) {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached filesystem root
		}
		dir = parent
	}
	return "", ErrNoProject
}
