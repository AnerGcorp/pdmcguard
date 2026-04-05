// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package daemon manages system service registration (launchd, systemd)
// and shell hook injection for the PDMCGuard daemon.
package daemon

// ServiceManager abstracts OS-specific service registration.
type ServiceManager interface {
	// Install registers the daemon as a system service.
	// binPath is the absolute path to the pdmcguard binary.
	Install(binPath string) error

	// Uninstall removes the daemon service registration.
	Uninstall() error

	// IsInstalled returns true if the service is registered.
	IsInstalled() bool

	// Start starts the daemon service.
	Start() error

	// Stop stops the daemon service.
	Stop() error
}

const (
	serviceLabel = "com.anergcorp.pdmcguard"
)
