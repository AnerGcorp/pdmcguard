// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bootstrap discovers project directories containing PDMC files
// during initial daemon startup.
package bootstrap

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/AnerGcorp/pdmcguard/internal/classifier"
	"github.com/AnerGcorp/pdmcguard/internal/watcher"
)

// Directories to skip when scanning $HOME (first-level children only).
// These are heavy or irrelevant for project discovery.
var skipDirs = map[string]bool{
	// macOS system directories
	"Library":      true,
	"Applications": true,
	"Movies":       true,
	"Music":        true,
	"Pictures":     true,
	"Public":       true,
	// Linux system directories
	"snap": true,
}

// DefaultRoots returns the user's home directory as the scan root.
// The scanner skips hidden directories, OS system directories, and
// classified directories (node_modules, .git, venvs, etc.) automatically.
func DefaultRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{home}
}

// Scan walks the given roots and returns directories that contain at least
// one PDMC file. Excluded directories (by inode in store) are skipped.
func Scan(store *classifier.ExcludeStore, roots []string) ([]string, error) {
	seen := make(map[string]bool)

	// Determine $HOME for skip-list matching
	home, _ := os.UserHomeDir()

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return fs.SkipDir
			}

			if d.IsDir() {
				name := d.Name()

				// Skip all hidden directories (dot-prefix)
				if strings.HasPrefix(name, ".") && path != root {
					return fs.SkipDir
				}

				// Skip known heavy/irrelevant directories at $HOME level
				if home != "" && filepath.Dir(path) == home && skipDirs[name] {
					return fs.SkipDir
				}

				// Check if this directory should be excluded by classifier
				cl, clErr := classifier.Classify(path)
				if clErr == nil && cl.Kind != classifier.Unknown {
					if store != nil {
						inode, inErr := classifier.InodeOf(path)
						if inErr == nil {
							store.Add(inode, cl.Kind, path)
						}
					}
					return fs.SkipDir
				}

				// Check inode-based exclusion
				if store != nil {
					inode, inErr := classifier.InodeOf(path)
					if inErr == nil && store.IsExcluded(inode) {
						return fs.SkipDir
					}
				}
				return nil
			}

			// Regular file — check if it's a PDMC file
			if watcher.IsPDMC(d.Name()) {
				dir := filepath.Dir(path)
				if !seen[dir] {
					seen[dir] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	return dirs, nil
}
