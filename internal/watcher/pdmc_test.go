// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package watcher

import "testing"

func TestIsPDMC(t *testing.T) {
	yes := []string{
		"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"pyproject.toml", "requirements.txt", "Pipfile", "Pipfile.lock",
		"Cargo.toml", "Cargo.lock",
		"go.mod", "go.sum",
		"Gemfile", "Gemfile.lock",
		"composer.json", "composer.lock",
	}
	for _, f := range yes {
		if !IsPDMC(f) {
			t.Errorf("IsPDMC(%q) = false, want true", f)
		}
	}

	no := []string{
		"index.js", "README.md", "Package.json", "PACKAGE.JSON",
		"go.mod.bak", "package.jsonl", "Cargo.toml.orig",
		"main.go", ".gitignore", "Dockerfile",
	}
	for _, f := range no {
		if IsPDMC(f) {
			t.Errorf("IsPDMC(%q) = true, want false", f)
		}
	}
}

func TestPDMCFiles_Count(t *testing.T) {
	if got := len(PDMCFiles); got != 16 {
		t.Errorf("PDMCFiles has %d entries, want 16", got)
	}
}
