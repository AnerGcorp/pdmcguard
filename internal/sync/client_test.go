// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package sync

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientHealthcheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	if err := c.Healthcheck(); err != nil {
		t.Fatal(err)
	}
}

func TestClientRegisterMachine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/machines" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Verify auth header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("auth = %q, want Bearer test-token", auth)
		}

		// Decode body
		var req MachineReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.MachineUUID != "test-uuid" {
			t.Errorf("machine_uuid = %q, want test-uuid", req.MachineUUID)
		}

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(IDResp{ID: "machine-id-123"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	id, err := c.RegisterMachine(MachineReq{
		MachineUUID: "test-uuid",
		Hostname:    "myhost",
		OS:          "darwin/arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "machine-id-123" {
		t.Errorf("id = %q, want machine-id-123", id)
	}
}

func TestClientUpsertProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/projects" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(IDResp{ID: "proj-id-456"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	id, err := c.UpsertProject(ProjectReq{
		ProjectHash: "abc",
		PDMCType:    "go.sum",
		Path:        "/home/user/project",
		Ecosystem:   "go",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "proj-id-456" {
		t.Errorf("id = %q, want proj-id-456", id)
	}
}

func TestClientCreateSnapshot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/snapshots" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}

		var req SnapshotReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if len(req.Packages) != 2 {
			t.Errorf("expected 2 packages, got %d", len(req.Packages))
		}

		w.WriteHeader(200)
		json.NewEncoder(w).Encode(IDResp{ID: "snap-id-789"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	id, err := c.CreateSnapshot(SnapshotReq{
		ProjectID:   "proj-1",
		MachineID:   "machine-1",
		ContentHash: "deadbeef",
		Trigger:     "watcher",
		Packages: []SnapshotPkg{
			{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
			{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "snap-id-789" {
		t.Errorf("id = %q, want snap-id-789", id)
	}
}

func TestClientPullAdvisories(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/advisories/match" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(MatchResp{
			Advisories: []MatchedAdvisory{
				{
					ID:          "adv-1",
					PackageName: "lodash",
					Ecosystem:   "npm",
					Severity:    "critical",
					Summary:     "Prototype Pollution",
				},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	resp, err := c.PullAdvisories(MatchReq{
		Packages: []MatchPkg{{Name: "lodash", Ecosystem: "npm"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Advisories) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(resp.Advisories))
	}
	if resp.Advisories[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical", resp.Advisories[0].Severity)
	}
}

func TestClientAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	err := c.Healthcheck()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}
