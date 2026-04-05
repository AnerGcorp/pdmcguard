// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lockfile parses dependency lock files to extract package lists.
package lockfile

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Package represents a single dependency with a pinned version.
type Package struct {
	Name    string
	Version string
}

// SemVer holds parsed semantic version components.
type SemVer struct {
	Major int
	Minor int
	Patch int
}

// ParseSemver extracts major.minor.patch from a version string.
// Tolerates leading "v", pre-release suffixes, and incomplete versions.
func ParseSemver(raw string) SemVer {
	s := strings.TrimPrefix(raw, "v")

	// Strip pre-release/build metadata (+build, -rc.1, etc.)
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}

	parts := strings.SplitN(s, ".", 3)
	sv := SemVer{}
	if len(parts) > 0 {
		sv.Major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) > 1 {
		sv.Minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) > 2 {
		sv.Patch, _ = strconv.Atoi(parts[2])
	}
	return sv
}

// lockFileForManifest maps manifest filenames to their adjacent lock file.
// When a manifest is changed, we parse the lock file instead (it has pinned versions).
var lockFileForManifest = map[string]string{
	"package.json":   "package-lock.json",
	"go.mod":         "go.sum",
	"Cargo.toml":     "Cargo.lock",
	"Gemfile":        "Gemfile.lock",
	"composer.json":  "composer.lock",
	"Pipfile":        "Pipfile.lock",
	"pyproject.toml": "requirements.txt",
}

// Parse reads a lock/manifest file and returns the packages it contains.
// For manifests (go.mod, package.json, etc.), it reads the adjacent lock file instead.
// Returns nil, nil if the file type is unsupported or the lock file doesn't exist.
func Parse(path, ecosystem string) ([]Package, error) {
	base := filepath.Base(path)
	dir := filepath.Dir(path)

	// If this is a manifest, redirect to the lock file
	if lockFile, ok := lockFileForManifest[base]; ok {
		path = filepath.Join(dir, lockFile)
		base = lockFile
	}

	switch base {
	case "go.sum":
		return parseGoSum(path)
	case "package-lock.json":
		return parsePackageLock(path)
	case "yarn.lock":
		return parseYarnLock(path)
	case "pnpm-lock.yaml":
		return parsePnpmLock(path)
	case "requirements.txt":
		return parseRequirements(path)
	case "Pipfile.lock":
		return parsePipfileLock(path)
	case "Cargo.lock":
		return parseCargoLock(path)
	case "Gemfile.lock":
		return parseGemfileLock(path)
	case "composer.lock":
		return parseComposerLock(path)
	default:
		return nil, fmt.Errorf("unsupported lock file: %s", base)
	}
}
