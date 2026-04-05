// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"encoding/json"
	"os"
	"strings"
)

// parsePackageLock parses a package-lock.json file.
// Supports lockfileVersion 1 (dependencies map) and 2/3 (packages map).
func parsePackageLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2/v3: packages map keyed by "node_modules/name"
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		// v1: dependencies map keyed by name
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var pkgs []Package

	if len(lock.Packages) > 0 {
		// v2/v3 format
		for key, pkg := range lock.Packages {
			if key == "" {
				continue // root package
			}
			// Extract package name from "node_modules/@scope/name" or "node_modules/name"
			name := key
			if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
				name = key[i+len("node_modules/"):]
			}
			if name == "" || pkg.Version == "" {
				continue
			}
			pkgs = append(pkgs, Package{Name: name, Version: pkg.Version})
		}
	} else if len(lock.Dependencies) > 0 {
		// v1 format
		for name, dep := range lock.Dependencies {
			if dep.Version == "" {
				continue
			}
			pkgs = append(pkgs, Package{Name: name, Version: dep.Version})
		}
	}

	return pkgs, nil
}
