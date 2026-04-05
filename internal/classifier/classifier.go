// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package classifier detects venvs, node_modules, and other directories to exclude.
package classifier

import (
	"os"
	"path/filepath"
	"strings"
)

// DirKind identifies the type of a classified directory.
type DirKind int

const (
	Unknown     DirKind = iota
	PythonVenv          // pyvenv.cfg exists
	NodeModules         // .package-lock.json exists
	GitDir              // HEAD + config + objects/ all exist
	RustTarget          // .rustc_info.json exists
	Pycache             // all entries are .pyc files
	GoVendor            // modules.txt exists
)

// String returns a human-readable name for the DirKind.
func (k DirKind) String() string {
	switch k {
	case PythonVenv:
		return "PythonVenv"
	case NodeModules:
		return "NodeModules"
	case GitDir:
		return "GitDir"
	case RustTarget:
		return "RustTarget"
	case Pycache:
		return "Pycache"
	case GoVendor:
		return "GoVendor"
	default:
		return "Unknown"
	}
}

// Classification holds the result of classifying a directory.
type Classification struct {
	Kind DirKind
	Path string
}

// Classify inspects a directory and returns its classification based on
// filesystem fingerprints (not directory name). Returns Unknown if no
// fingerprint matches.
func Classify(dir string) (Classification, error) {
	c := Classification{Path: dir}

	// PythonVenv: pyvenv.cfg exists
	if fileExists(filepath.Join(dir, "pyvenv.cfg")) {
		c.Kind = PythonVenv
		return c, nil
	}

	// NodeModules: .package-lock.json exists
	if fileExists(filepath.Join(dir, ".package-lock.json")) {
		c.Kind = NodeModules
		return c, nil
	}

	// GitDir: HEAD + config + objects/ all exist
	if fileExists(filepath.Join(dir, "HEAD")) &&
		fileExists(filepath.Join(dir, "config")) &&
		dirExists(filepath.Join(dir, "objects")) {
		c.Kind = GitDir
		return c, nil
	}

	// RustTarget: .rustc_info.json exists
	if fileExists(filepath.Join(dir, ".rustc_info.json")) {
		c.Kind = RustTarget
		return c, nil
	}

	// Pycache: non-empty dir where all entries are .pyc files
	if isPycache(dir) {
		c.Kind = Pycache
		return c, nil
	}

	// GoVendor: modules.txt exists
	if fileExists(filepath.Join(dir, "modules.txt")) {
		c.Kind = GoVendor
		return c, nil
	}

	return c, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isPycache(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pyc") {
			return false
		}
	}
	return true
}
