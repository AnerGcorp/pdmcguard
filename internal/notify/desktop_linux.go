// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package notify

import (
	"fmt"
	"os/exec"
)

// SendDesktopNotification fires a Linux notification via notify-send.
func SendDesktopNotification(title, subtitle, body string) error {
	// notify-send doesn't have a subtitle concept — combine title+subtitle
	heading := title
	if subtitle != "" {
		heading = title + " — " + subtitle
	}

	// Use critical urgency for security alerts
	cmd := exec.Command("notify-send", "-u", "critical", heading, body)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("notify-send: %w", err)
	}
	return nil
}
