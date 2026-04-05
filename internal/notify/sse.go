// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package notify provides SSE-based desktop alert notifications.
// The daemon connects to a cloud SSE endpoint and fires OS-level
// notifications for Critical/High severity alerts.
package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// AlertEvent is a single alert received from the SSE stream.
type AlertEvent struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	FixVersion  string `json:"fix_version"`
	ProjectPath string `json:"project_path"`
	AdvisoryURL string `json:"advisory_url"`
	AdvisoryID  string `json:"advisory_id"`
}

// SSEListener connects to the daemon-sse edge function and dispatches
// desktop notifications for Critical/High alerts.
type SSEListener struct {
	sseURL    string
	authToken string
	client    *http.Client

	mu            sync.Mutex
	lastConnected time.Time
	running       bool
}

// NewSSEListener creates a new SSE listener.
// apiURL is the base API URL (e.g. "https://ouxnnyjpigtcwzgemgxg.supabase.co/functions/v1/daemon-api").
// The SSE endpoint is derived as the sibling function: replace /daemon-api path
// with /daemon-sse in the Supabase functions URL.
func NewSSEListener(apiURL, authToken string) *SSEListener {
	// apiURL looks like "https://xxx.supabase.co/functions/v1/daemon-api"
	// SSE endpoint is    "https://xxx.supabase.co/functions/v1/daemon-sse"
	sseURL := strings.Replace(apiURL, "/daemon-api", "/daemon-sse", 1)
	if sseURL == apiURL {
		// Fallback: append /sse to base URL
		sseURL = strings.TrimSuffix(apiURL, "/") + "/sse"
	}

	return &SSEListener{
		sseURL:    sseURL,
		authToken: authToken,
		client: &http.Client{
			// No timeout — SSE connections are long-lived.
			// The server closes after 120s; we reconnect.
			Timeout: 0,
		},
	}
}

// Run starts the SSE listener loop. It connects, reads events, and
// auto-reconnects with exponential backoff on failure.
// Blocks until ctx is cancelled.
func (l *SSEListener) Run(ctx context.Context) {
	l.mu.Lock()
	l.running = true
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		l.running = false
		l.mu.Unlock()
	}()

	backoff := 5 * time.Second
	maxBackoff := 5 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := l.connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return // Context cancelled — clean shutdown
			}
			fmt.Fprintf(os.Stderr, "[sse] disconnected: %v (reconnecting in %s)\n", err, backoff)

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff: 5s → 10s → 20s → 40s → ... → 5min cap
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			// Clean close (server sent "reconnect") — reconnect immediately
			backoff = 5 * time.Second
		}
	}
}

// LastConnected returns the timestamp of the last successful SSE connection.
func (l *SSEListener) LastConnected() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastConnected
}

// IsRunning returns true if the SSE listener goroutine is active.
func (l *SSEListener) IsRunning() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.running
}

// connect opens a single SSE connection and reads events until the server
// closes it or an error occurs.
func (l *SSEListener) connect(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", l.sseURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+l.authToken)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "pdmcguard-daemon/1.0")

	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	l.mu.Lock()
	l.lastConnected = time.Now()
	l.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[sse] connected to %s\n", l.sseURL)

	// Read SSE stream line by line
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// SSE format: "data: {json}\n" or ": ping\n" (comment/keepalive)
		if strings.HasPrefix(line, "data: ") {
			payload := line[6:] // Strip "data: " prefix
			l.handleEvent(payload)
		}
		// Ignore comments (": ping") and empty lines
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read stream: %w", err)
	}

	// Stream ended cleanly (server closed after 120s)
	return nil
}

// handleEvent parses a JSON event and dispatches desktop notifications.
func (l *SSEListener) handleEvent(payload string) {
	var ev AlertEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		fmt.Fprintf(os.Stderr, "[sse] invalid event: %v\n", err)
		return
	}

	switch ev.Type {
	case "connected":
		fmt.Fprintf(os.Stderr, "[sse] stream active\n")
	case "reconnect":
		fmt.Fprintf(os.Stderr, "[sse] server requested reconnect\n")
	case "alert":
		l.handleAlert(ev)
	}
}

// handleAlert fires an OS desktop notification for Critical/High alerts.
func (l *SSEListener) handleAlert(ev AlertEvent) {
	sev := strings.ToLower(ev.Severity)

	// Only fire desktop notifications for critical and high severity
	if sev != "critical" && sev != "high" {
		fmt.Fprintf(os.Stderr, "[sse] alert %s (%s) — skipped (severity: %s)\n",
			ev.PackageName, ev.Version, sev)
		return
	}

	title := "PDMCGuard"
	// Capitalize first letter of severity
	sevLabel := strings.ToUpper(sev[:1]) + sev[1:]
	subtitle := fmt.Sprintf("%s Alert", sevLabel)
	body := fmt.Sprintf("%s@%s — %s", ev.PackageName, ev.Version, ev.Title)

	fmt.Fprintf(os.Stderr, "[sse] alert: %s\n", body)

	if err := SendDesktopNotification(title, subtitle, body); err != nil {
		fmt.Fprintf(os.Stderr, "[sse] desktop notification failed: %v\n", err)
	}
}
