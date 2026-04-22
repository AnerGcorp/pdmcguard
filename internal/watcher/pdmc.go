// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package watcher

import (
	"os"
	"path/filepath"
)

// PDMCFiles maps dependency filenames to their ecosystem.
// Case-sensitive — "Package.json" does NOT match.
var PDMCFiles = map[string]string{
	// Node.js
	"package.json":      "npm",
	"package-lock.json": "npm",
	"yarn.lock":         "npm",
	"pnpm-lock.yaml":    "npm",
	// Python
	"pyproject.toml":    "pypi",
	"requirements.txt":  "pypi",
	"Pipfile":           "pypi",
	"Pipfile.lock":      "pypi",
	// Rust
	"Cargo.toml": "crates.io",
	"Cargo.lock": "crates.io",
	// Go
	"go.mod": "go",
	"go.sum": "go",
	// Ruby
	"Gemfile":      "rubygems",
	"Gemfile.lock": "rubygems",
	// PHP
	"composer.json": "packagist",
	"composer.lock": "packagist",
}

// IsPDMC returns true if the filename is a known dependency manifest or lockfile.
func IsPDMC(filename string) bool {
	_, ok := PDMCFiles[filename]
	return ok
}

// lockfilePreference lists each ecosystem's PDMC filenames from most
// authoritative to least (lockfiles before manifests). The baseline scanner
// emits one canonical event per (dir, ecosystem) pair by picking the
// highest-ranked file that's actually on disk — that way we don't redo the
// same classifier roundtrip twice for a dir containing e.g. both
// package.json and package-lock.json.
var lockfilePreference = map[string][]string{
	"npm":       {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "package.json"},
	"pypi":      {"Pipfile.lock", "requirements.txt", "Pipfile", "pyproject.toml"},
	"crates.io": {"Cargo.lock", "Cargo.toml"},
	"go":        {"go.sum", "go.mod"},
	"rubygems":  {"Gemfile.lock", "Gemfile"},
	"packagist": {"composer.lock", "composer.json"},
}

// EnumeratePDMCFiles scans each dir non-recursively and returns one
// PDMCChangeEvent per (dir, ecosystem) pair found, preferring lockfiles
// over manifests. Used by the startup baseline scan; kept in this package
// so PDMCFiles stays the single source of truth.
//
// Entries that aren't regular files (directories, symlinks, sockets) are
// skipped — bootstrap.Scan already filters vendored trees, but enumeration
// is defensive about what else might be sitting in a project root.
func EnumeratePDMCFiles(dirs []string) []PDMCChangeEvent {
	var events []PDMCChangeEvent
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		// Collect the PDMC filenames present in this dir, grouped by ecosystem.
		present := make(map[string]map[string]struct{}) // eco → {filename}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			name := e.Name()
			eco, ok := PDMCFiles[name]
			if !ok {
				continue
			}
			if present[eco] == nil {
				present[eco] = make(map[string]struct{})
			}
			present[eco][name] = struct{}{}
		}

		// For each ecosystem, emit one event using the top-ranked filename.
		// If an ecosystem has no preference entry (shouldn't happen — every
		// ecosystem in PDMCFiles is represented), fall through to any match.
		for eco, names := range present {
			pref := lockfilePreference[eco]
			var chosen string
			for _, candidate := range pref {
				if _, ok := names[candidate]; ok {
					chosen = candidate
					break
				}
			}
			if chosen == "" {
				for n := range names {
					chosen = n
					break
				}
			}
			events = append(events, PDMCChangeEvent{
				Path:      filepath.Join(dir, chosen),
				Dir:       dir,
				Ecosystem: eco,
			})
		}
	}
	return events
}
