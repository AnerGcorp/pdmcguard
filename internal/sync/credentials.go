// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package sync

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/AnerGcorp/pdmcguard/internal/config"
)

const (
	defaultAPIURL   = "https://api.pdmcguard.com/v1"
	credentialsFile = "credentials.json"
)

var ErrNoCredentials = errors.New("no credentials found — run 'pdmcguard login' to authenticate")

// Credentials holds API authentication data.
type Credentials struct {
	APIURL       string `json:"api_url"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// LoadCredentials reads credentials from ~/.pdmcguard/credentials.json.
// Falls back to PDMCGUARD_API_URL env var for the API URL.
// Returns ErrNoCredentials if the file does not exist.
func LoadCredentials() (*Credentials, error) {
	path := config.FilePath(credentialsFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoCredentials
		}
		return nil, err
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}

	// Override API URL from env if set
	if envURL := os.Getenv("PDMCGUARD_API_URL"); envURL != "" {
		creds.APIURL = envURL
	}

	// Default API URL
	if creds.APIURL == "" {
		creds.APIURL = defaultAPIURL
	}

	if creds.AccessToken == "" {
		return nil, ErrNoCredentials
	}

	return &creds, nil
}
