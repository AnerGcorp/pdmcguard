// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package notify

import (
	"fmt"
	"os/exec"
	"strings"
)

// SendDesktopNotification fires a macOS notification via osascript.
func SendDesktopNotification(title, subtitle, body string) error {
	// Escape double quotes for AppleScript
	escape := func(s string) string {
		return strings.ReplaceAll(s, `"`, `\"`)
	}

	script := fmt.Sprintf(
		`display notification "%s" with title "%s" subtitle "%s"`,
		escape(body), escape(title), escape(subtitle),
	)

	cmd := exec.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("osascript: %w", err)
	}
	return nil
}
