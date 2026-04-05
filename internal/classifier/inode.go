// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package classifier

import (
	"fmt"
	"syscall"
)

// InodeOf returns the inode number of the given path.
// Unix-only (macOS + Linux). Windows support deferred to Phase 2.
func InodeOf(path string) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return stat.Ino, nil
}
