// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package watcher

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
