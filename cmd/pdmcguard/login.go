// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/AnerGcorp/pdmcguard/internal/config"
	psync "github.com/AnerGcorp/pdmcguard/internal/sync"
)

const defaultAPIURL = "https://api.pdmcguard.com/v1"

func cmdLogin(args []string) {
	apiURL := defaultAPIURL
	for i, a := range args {
		if a == "--api-url" && i+1 < len(args) {
			apiURL = args[i+1]
		}
	}

	// Check env var override
	if envURL := os.Getenv("PDMCGUARD_API_URL"); envURL != "" {
		apiURL = envURL
	}

	fmt.Println("PDMCGuard Login")
	fmt.Println()
	fmt.Println("  Get your API token at: https://pdmcguard.com/settings/api-tokens")
	fmt.Println()
	fmt.Print("Enter your API token: ")

	reader := bufio.NewReader(os.Stdin)
	token, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading input: %v\n", err)
		os.Exit(1)
	}
	token = strings.TrimSpace(token)

	if token == "" {
		fmt.Fprintln(os.Stderr, "error: API key cannot be empty")
		os.Exit(1)
	}

	// Verify the token works
	client := psync.NewClient(apiURL, token)
	if err := client.Healthcheck(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: API health check failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "Credentials will be saved anyway — the API may be temporarily unavailable.")
	}

	// Write credentials
	creds := struct {
		APIURL      string `json:"api_url"`
		AccessToken string `json:"access_token"`
	}{
		APIURL:      apiURL,
		AccessToken: token,
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal credentials: %v\n", err)
		os.Exit(1)
	}

	credPath := config.FilePath("credentials.json")
	if err := os.WriteFile(credPath, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "error: write credentials: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("Authenticated successfully!")
	fmt.Printf("Credentials saved to: %s\n", credPath)
	fmt.Println()
	fmt.Println("If the daemon is running, restart it to connect:")
	fmt.Println("  launchctl stop com.anergcorp.pdmcguard && launchctl start com.anergcorp.pdmcguard")
}
