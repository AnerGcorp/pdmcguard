// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"bufio"
	"os"
	"strings"
)

// parseGemfileLock parses a Gemfile.lock file.
// Format: After "GEM" section, "  specs:" header, then indented "    name (version)" lines.
func parseGemfileLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	inSpecs := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Detect "  specs:" section (under GEM, PATH, or GIT)
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}

		if !inSpecs {
			continue
		}

		// Section ends when we hit a non-indented line or empty line
		if line == "" || (len(line) > 0 && line[0] != ' ') {
			inSpecs = false
			continue
		}

		trimmed := strings.TrimSpace(line)

		// Top-level gems are indented 4 spaces (exactly), sub-dependencies 6+
		// We want the 4-space indented ones: "    name (version)"
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent != 4 {
			continue
		}

		// Parse "name (version)"
		paren := strings.Index(trimmed, " (")
		if paren < 0 {
			continue
		}
		name := trimmed[:paren]
		ver := trimmed[paren+2:]
		ver = strings.TrimSuffix(ver, ")")

		if name != "" && ver != "" {
			pkgs = append(pkgs, Package{Name: name, Version: ver})
		}
	}

	return pkgs, scanner.Err()
}
