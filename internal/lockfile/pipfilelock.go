// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"encoding/json"
	"os"
	"strings"
)

// parsePipfileLock parses a Pipfile.lock file.
// Format: JSON with "default" and "develop" sections mapping package names
// to objects with a "version" field (e.g., "==1.2.3").
func parsePipfileLock(path string) ([]Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var lock struct {
		Default map[string]pipfilePkg `json:"default"`
		Develop map[string]pipfilePkg `json:"develop"`
	}

	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}

	var pkgs []Package
	for name, pkg := range lock.Default {
		ver := cleanPipfileVersion(pkg.Version)
		if ver != "" {
			pkgs = append(pkgs, Package{Name: name, Version: ver})
		}
	}
	for name, pkg := range lock.Develop {
		ver := cleanPipfileVersion(pkg.Version)
		if ver != "" {
			pkgs = append(pkgs, Package{Name: name, Version: ver})
		}
	}

	return pkgs, nil
}

type pipfilePkg struct {
	Version string `json:"version"`
}

// cleanPipfileVersion strips the "==" prefix from Pipfile.lock versions.
func cleanPipfileVersion(v string) string {
	return strings.TrimPrefix(v, "==")
}
