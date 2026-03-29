// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package sync

import (
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/google/uuid"
)

const machineIDFile = "machine_id"

// MachineUUID returns a stable identifier for this machine.
// Generated once, then stored in ~/.pdmcguard/machine_id.
func MachineUUID() string {
	path := config.FilePath(machineIDFile)

	// Try reading existing ID
	data, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id
		}
	}

	// Generate deterministic UUID from hostname
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	hash := sha256.Sum256([]byte("pdmcguard-machine:" + hostname))
	id := uuid.NewSHA1(uuid.NameSpaceURL, hash[:]).String()

	// Persist for stability
	_ = os.WriteFile(path, []byte(id+"\n"), 0o600)
	return id
}

// MachineHostname returns the current hostname.
func MachineHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// MachineOS returns the operating system identifier.
func MachineOS() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}
