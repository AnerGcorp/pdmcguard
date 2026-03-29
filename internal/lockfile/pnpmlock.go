// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"bufio"
	"os"
	"strings"
)

// parsePnpmLock parses a pnpm-lock.yaml file.
// We parse line-by-line to avoid a YAML library dependency.
//
// pnpm v6 format:
//
//	packages:
//	  /lodash/4.17.21:
//	    ...
//
// pnpm v9+ format:
//
//	packages:
//	  lodash@4.17.21:
//	    ...
//
// Scoped: /@babel/core@7.24.0: or /@babel/core/7.24.0:
func parsePnpmLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	seen := make(map[string]bool)
	inPackages := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Detect "packages:" section
		if strings.TrimSpace(line) == "packages:" {
			inPackages = true
			continue
		}

		if !inPackages {
			continue
		}

		// Section ends at next top-level key (no indentation)
		if len(line) > 0 && line[0] != ' ' {
			break
		}

		// Package entries are indented 2 spaces and end with ":"
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, ":") {
			continue
		}

		// Must be a direct child (2-space indent), not a nested property
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent != 2 {
			continue
		}

		trimmed = strings.TrimSuffix(trimmed, ":")
		// Strip surrounding quotes (scoped packages are quoted in YAML)
		trimmed = strings.Trim(trimmed, "'\"")
		name, ver := parsePnpmPackageKey(trimmed)
		if name == "" || ver == "" {
			continue
		}

		key := name + "@" + ver
		if !seen[key] {
			seen[key] = true
			pkgs = append(pkgs, Package{Name: name, Version: ver})
		}
	}

	return pkgs, scanner.Err()
}

// parsePnpmPackageKey extracts name and version from a pnpm package key.
// Formats:
//
//	/lodash/4.17.21           → lodash, 4.17.21
//	/@babel/core/7.24.0       → @babel/core, 7.24.0
//	lodash@4.17.21            → lodash, 4.17.21
//	@babel/core@7.24.0        → @babel/core, 7.24.0
func parsePnpmPackageKey(key string) (string, string) {
	// Strip leading slash (pnpm v6)
	key = strings.TrimPrefix(key, "/")

	// Try @ separator first (pnpm v9+)
	// For scoped packages (@scope/name@ver), find the last @
	if i := strings.LastIndex(key, "@"); i > 0 {
		name := key[:i]
		ver := key[i+1:]
		// Verify this looks like a version (starts with digit)
		if len(ver) > 0 && ver[0] >= '0' && ver[0] <= '9' {
			return name, ver
		}
	}

	// Try / separator (pnpm v6)
	// For scoped packages (@scope/name/ver), find the last /
	if i := strings.LastIndex(key, "/"); i > 0 {
		name := key[:i]
		ver := key[i+1:]
		if len(ver) > 0 && ver[0] >= '0' && ver[0] <= '9' {
			return name, ver
		}
	}

	return "", ""
}
