// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"encoding/json"
	"os"
	"strings"
)

// parseComposerLock parses a composer.lock file.
// Format: JSON with "packages" and "packages-dev" arrays.
func parseComposerLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var lock struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}

	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var pkgs []Package
	for _, p := range lock.Packages {
		if p.Name != "" && p.Version != "" {
			pkgs = append(pkgs, Package{Name: p.Name, Version: cleanComposerVersion(p.Version)})
		}
	}
	for _, p := range lock.PackagesDev {
		if p.Name != "" && p.Version != "" {
			pkgs = append(pkgs, Package{Name: p.Name, Version: cleanComposerVersion(p.Version)})
		}
	}

	return pkgs, nil
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// cleanComposerVersion strips the "v" prefix common in Composer versions.
func cleanComposerVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}
