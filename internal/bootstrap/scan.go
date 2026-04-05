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

	"github.com/AnerGcorp/pdmcguard/internal/classifier"
	"github.com/AnerGcorp/pdmcguard/internal/watcher"
)

// DefaultRoots returns common project root directories that exist on this machine.
func DefaultRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	candidates := []string{
		filepath.Join(home, "projects"),
		filepath.Join(home, "Projects"),
		filepath.Join(home, "code"),
		filepath.Join(home, "Code"),
		filepath.Join(home, "work"),
		filepath.Join(home, "Work"),
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "dev"),
		filepath.Join(home, "Dev"),
	}
	var roots []string
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			roots = append(roots, c)
		}
	}
	return roots
}

// Scan walks the given roots and returns directories that contain at least
// one PDMC file. Excluded directories (by inode in store) are skipped.
func Scan(store *classifier.ExcludeStore, roots []string) ([]string, error) {
	seen := make(map[string]bool)

	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return fs.SkipDir
			}

			if d.IsDir() {
				// Check if this directory should be excluded
				cl, clErr := classifier.Classify(path)
				if clErr == nil && cl.Kind != classifier.Unknown {
					// Auto-exclude: add to store if we have one
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
