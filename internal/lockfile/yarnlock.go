// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"bufio"
	"os"
	"strings"
)

// parseYarnLock parses a yarn.lock file (v1 classic format).
// Format:
//
//	"name@^1.0.0", "name@~1.2.0":
//	  version "1.2.3"
//	  resolved "..."
//	  ...
//
// Also handles yarn berry (v2+) which uses a similar but slightly different format.
func parseYarnLock(path string) ([]Package, error) {
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
	var curName string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Package header line: starts at column 0 (no indentation), ends with ":"
		if len(line) > 0 && line[0] != ' ' && strings.HasSuffix(strings.TrimSpace(line), ":") {
			curName = extractYarnPackageName(line)
			continue
		}

		// Version line: indented, starts with "version"
		trimmed := strings.TrimSpace(line)
		if curName != "" && strings.HasPrefix(trimmed, "version ") {
			ver := trimmed[len("version "):]
			ver = strings.Trim(ver, "\"")

			key := curName + "@" + ver
			if !seen[key] {
				seen[key] = true
				pkgs = append(pkgs, Package{Name: curName, Version: ver})
			}
			curName = ""
		}
	}

	return pkgs, scanner.Err()
}

// extractYarnPackageName extracts the package name from a yarn.lock header line.
// e.g., `"lodash@^4.17.21":` → "lodash"
// e.g., `"@babel/core@^7.0.0", "@babel/core@^7.12.0":` → "@babel/core"
func extractYarnPackageName(line string) string {
	line = strings.TrimSuffix(strings.TrimSpace(line), ":")

	// Take the first entry (before comma if multiple)
	if i := strings.Index(line, ","); i >= 0 {
		line = line[:i]
	}

	line = strings.Trim(line, "\" ")

	// Find the last @ that separates name from version range
	// For scoped packages like @babel/core@^7.0.0, we need the second @
	atIdx := strings.LastIndex(line, "@")
	if atIdx <= 0 {
		return line
	}

	return line[:atIdx]
}
