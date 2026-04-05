// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a generic REST client for the PDMCGuard API.
// It has zero knowledge of Supabase — it talks to a configurable API endpoint.
type Client struct {
	baseURL    string
	authToken  string
	httpClient *http.Client
}

// NewClient creates a new API client.
func NewClient(baseURL, authToken string) *Client {
	return &Client{
		baseURL:   baseURL,
		authToken: authToken,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ── Request/Response types ──────────────────────────────────────────────────

// MachineReq is the request body for POST /machines.
type MachineReq struct {
	MachineUUID string `json:"machine_uuid"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
}

// IDResp is a generic response containing an ID.
type IDResp struct {
	ID string `json:"id"`
}

// ProjectReq is the request body for PUT /projects.
type ProjectReq struct {
	ProjectHash string `json:"project_hash"`
	PDMCType    string `json:"pdmc_type"`
	Path        string `json:"path"`
	GitRemote   string `json:"git_remote,omitempty"`
	Ecosystem   string `json:"ecosystem"`
}

// SnapshotReq is the request body for POST /snapshots.
type SnapshotReq struct {
	ProjectID   string       `json:"project_id"`
	MachineID   string       `json:"machine_id"`
	ContentHash string       `json:"content_hash"`
	GitBranch   string       `json:"git_branch,omitempty"`
	GitCommit   string       `json:"git_commit,omitempty"`
	Trigger     string       `json:"trigger"`
	Packages    []SnapshotPkg `json:"packages"`
}

// SnapshotPkg is a package entry within a snapshot request.
type SnapshotPkg struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// MatchReq is the request body for POST /advisories/match.
type MatchReq struct {
	Packages []MatchPkg `json:"packages"`
}

// MatchPkg identifies a package for advisory matching.
type MatchPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// MatchResp is the response from POST /advisories/match.
type MatchResp struct {
	Advisories []MatchedAdvisory `json:"advisories"`
}

// MatchedAdvisory is an advisory returned by the match endpoint.
type MatchedAdvisory struct {
	ID          string `json:"id"`
	PackageName string `json:"package_name"`
	Ecosystem   string `json:"ecosystem"`
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
}

// ── API methods ─────────────────────────────────────────────────────────────

// Healthcheck verifies the API is reachable.
func (c *Client) Healthcheck() error {
	_, err := c.doRequest("GET", "/health", nil)
	return err
}

// RegisterMachine upserts this machine and returns its server-side ID.
func (c *Client) RegisterMachine(req MachineReq) (string, error) {
	body, err := c.doRequest("POST", "/machines", req)
	if err != nil {
		return "", err
	}
	var resp IDResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode machine response: %w", err)
	}
	return resp.ID, nil
}

// UpsertProject upserts a project and returns its server-side ID.
func (c *Client) UpsertProject(req ProjectReq) (string, error) {
	body, err := c.doRequest("PUT", "/projects", req)
	if err != nil {
		return "", err
	}
	var resp IDResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode project response: %w", err)
	}
	return resp.ID, nil
}

// CreateSnapshot creates a snapshot with its packages and returns the snapshot ID.
func (c *Client) CreateSnapshot(req SnapshotReq) (string, error) {
	body, err := c.doRequest("POST", "/snapshots", req)
	if err != nil {
		return "", err
	}
	var resp IDResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode snapshot response: %w", err)
	}
	return resp.ID, nil
}

// PullAdvisories matches packages against known advisories.
func (c *Client) PullAdvisories(req MatchReq) (*MatchResp, error) {
	body, err := c.doRequest("POST", "/advisories/match", req)
	if err != nil {
		return nil, err
	}
	var resp MatchResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode advisories response: %w", err)
	}
	return &resp, nil
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

func (c *Client) doRequest(method, path string, payload interface{}) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(data)
	}

	url := c.baseURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("User-Agent", "pdmcguard-daemon/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("api %s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
