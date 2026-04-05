// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/AnerGcorp/pdmcguard/internal/config"
)

// SystemdService manages PDMCGuard as a systemd user service on Linux.
type SystemdService struct{}

// NewServiceManager returns a systemd-based service manager on Linux.
func NewServiceManager() ServiceManager {
	return &SystemdService{}
}

func (s *SystemdService) unitPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", "pdmcguard.service")
}

func (s *SystemdService) Install(binPath string) error {
	logPath := config.FilePath("daemon.log")

	unit := fmt.Sprintf(`[Unit]
Description=PDMCGuard — Passive Dependency Monitor & Compromise Guard
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5
StandardOutput=append:%s
StandardError=append:%s

[Install]
WantedBy=default.target
`, binPath, logPath, logPath)

	// Ensure systemd user dir exists
	dir := filepath.Dir(s.unitPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create systemd user dir: %w", err)
	}

	if err := os.WriteFile(s.unitPath(), []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	// Reload and enable
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "--user", "enable", "--now", "pdmcguard.service").Run(); err != nil {
		return fmt.Errorf("systemctl enable: %w", err)
	}

	return nil
}

func (s *SystemdService) Uninstall() error {
	if !s.IsInstalled() {
		return nil
	}

	_ = exec.Command("systemctl", "--user", "disable", "--now", "pdmcguard.service").Run()

	if err := os.Remove(s.unitPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}

	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	return nil
}

func (s *SystemdService) IsInstalled() bool {
	_, err := os.Stat(s.unitPath())
	return err == nil
}

func (s *SystemdService) Start() error {
	return exec.Command("systemctl", "--user", "start", "pdmcguard.service").Run()
}

func (s *SystemdService) Stop() error {
	return exec.Command("systemctl", "--user", "stop", "pdmcguard.service").Run()
}
