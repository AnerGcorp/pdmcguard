// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"bufio"
	"os"
	"strings"
)

// parseCargoLock parses a Cargo.lock file.
// Format: TOML-like [[package]] blocks with name and version fields.
// We parse line-by-line to avoid a TOML library dependency.
func parseCargoLock(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var pkgs []Package
	var curName, curVersion string
	inPackage := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			// Flush previous package
			if inPackage && curName != "" && curVersion != "" {
				pkgs = append(pkgs, Package{Name: curName, Version: curVersion})
			}
			curName = ""
			curVersion = ""
			inPackage = true
			continue
		}

		if !inPackage {
			continue
		}

		// Empty line or new section ends the block
		if line == "" || (strings.HasPrefix(line, "[") && line != "[[package]]") {
			if curName != "" && curVersion != "" {
				pkgs = append(pkgs, Package{Name: curName, Version: curVersion})
			}
			curName = ""
			curVersion = ""
			inPackage = strings.HasPrefix(line, "[[package]]")
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			curName = unquoteTOML(line[len("name = "):])
		} else if strings.HasPrefix(line, "version = ") {
			curVersion = unquoteTOML(line[len("version = "):])
		}
	}

	// Flush last package
	if inPackage && curName != "" && curVersion != "" {
		pkgs = append(pkgs, Package{Name: curName, Version: curVersion})
	}

	return pkgs, scanner.Err()
}

// unquoteTOML strips surrounding quotes from a TOML string value.
func unquoteTOML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
