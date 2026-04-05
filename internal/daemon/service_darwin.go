// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/AnerGcorp/pdmcguard/internal/config"
)

// LaunchdService manages PDMCGuard as a macOS launchd LaunchAgent.
type LaunchdService struct{}

// NewServiceManager returns a launchd-based service manager on macOS.
func NewServiceManager() ServiceManager {
	return &LaunchdService{}
}

func (s *LaunchdService) plistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist")
}

func (s *LaunchdService) Install(binPath string) error {
	logPath := config.FilePath("daemon.log")

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
`, serviceLabel, binPath, logPath, logPath)

	// Ensure LaunchAgents directory exists
	dir := filepath.Dir(s.plistPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create LaunchAgents dir: %w", err)
	}

	if err := os.WriteFile(s.plistPath(), []byte(plist), 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// Load the service
	if err := exec.Command("launchctl", "load", s.plistPath()).Run(); err != nil {
		return fmt.Errorf("launchctl load: %w", err)
	}

	return nil
}

func (s *LaunchdService) Uninstall() error {
	if !s.IsInstalled() {
		return nil
	}

	// Unload first (ignore error if not loaded)
	_ = exec.Command("launchctl", "unload", s.plistPath()).Run()

	if err := os.Remove(s.plistPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}

	return nil
}

func (s *LaunchdService) IsInstalled() bool {
	_, err := os.Stat(s.plistPath())
	return err == nil
}

func (s *LaunchdService) Start() error {
	return exec.Command("launchctl", "start", serviceLabel).Run()
}

func (s *LaunchdService) Stop() error {
	return exec.Command("launchctl", "stop", serviceLabel).Run()
}
