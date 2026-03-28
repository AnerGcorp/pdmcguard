// PDMCGuard — Passive Dependency Monitor & Critical Guard
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
func FindProjectDir(startDir string) (string, error) {
	dir := startDir
	for i := 0; i < maxDepth; i++ {
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
