// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"bufio"
	"os"
	"strings"
)

// parseRequirements parses a requirements.txt file.
// Format: name==version (pinned), name>=version (range — skip), -r file (include — skip).
// Only extracts pinned versions (==).
func parseRequirements(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, options, includes
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "-") || strings.HasPrefix(line, "http") {
			continue
		}

		// Strip inline comments
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}

		// Strip environment markers (e.g., ; python_version >= "3.6")
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}

		// Look for == (pinned version)
		if i := strings.Index(line, "=="); i >= 0 {
			name := strings.TrimSpace(line[:i])
			ver := strings.TrimSpace(line[i+2:])
			if name != "" && ver != "" {
				pkgs = append(pkgs, Package{Name: name, Version: ver})
			}
		}
	}

	return pkgs, scanner.Err()
}
