// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package lockfile

import (
	"bufio"
	"os"
	"strings"
)

// parseGoSum parses a go.sum file.
// Format: <module> <version>[/go.mod] <hash>
// We deduplicate by module+version (skip /go.mod duplicate lines).
func parseGoSum(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]bool)
	var pkgs []Package

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		name := fields[0]
		ver := fields[1]

		// Strip /go.mod suffix from version
		ver = strings.TrimSuffix(ver, "/go.mod")

		key := name + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true

		pkgs = append(pkgs, Package{Name: name, Version: ver})
	}

	return pkgs, scanner.Err()
}
