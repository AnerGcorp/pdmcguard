// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sync provides offline-resilient sync to the PDMCGuard API.
package sync

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	gosync "sync"
	"time"

	"github.com/AnerGcorp/pdmcguard/internal/cache"
	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/git"
	"github.com/AnerGcorp/pdmcguard/internal/lockfile"
	"github.com/AnerGcorp/pdmcguard/internal/watcher"
)

// Engine bridges the local daemon with the remote PDMCGuard API.
type Engine struct {
	client    *Client
	cache     *cache.Store
	queue     *Queue
	machineID string
	online    bool
	mu        gosync.Mutex
}

// New creates a sync engine. It tries to load credentials and connect.
// If credentials are missing or the API is unreachable, the engine runs
// in offline mode (queues events for later).
func New(cacheStore *cache.Store) (*Engine, error) {
	q, err := OpenQueue(config.FilePath("queue.db"))
	if err != nil {
		return nil, fmt.Errorf("open sync queue: %w", err)
	}

	e := &Engine{
		cache: cacheStore,
		queue: q,
	}

	creds, err := LoadCredentials()
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			fmt.Fprintln(os.Stderr, "[sync] no credentials — running offline (run 'pdmcguard login' to connect)")
			return e, nil
		}
		return nil, fmt.Errorf("load credentials: %w", err)
	}

	e.client = NewClient(creds.APIURL, creds.AccessToken)

	// Register machine
	mid, err := e.client.RegisterMachine(MachineReq{
		MachineUUID: MachineUUID(),
		Hostname:    MachineHostname(),
		OS:          MachineOS(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sync] API unreachable — running offline (%v)\n", err)
		return e, nil
	}

	e.machineID = mid
	e.online = true
	fmt.Fprintf(os.Stderr, "[sync] connected to %s (machine: %.8s)\n", creds.APIURL, mid)

	// Drain any queued items from previous offline session
	go e.drainQueue()

	return e, nil
}

// Close releases sync engine resources.
func (e *Engine) Close() error {
	if e.queue != nil {
		return e.queue.Close()
	}
	return nil
}

// Online returns true if the engine has an active API connection.
func (e *Engine) Online() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.online
}

// HandleChange processes a PDMC file change event.
func (e *Engine) HandleChange(ev watcher.PDMCChangeEvent, gitInfo *git.Info, trigger string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Find the lock file to parse
	lockPath := resolveLockPath(ev.Path, ev.Ecosystem)
	if lockPath == "" {
		return
	}

	// Content hash for dedup
	contentHash, err := hashFile(lockPath)
	if err != nil {
		return
	}

	// Check if content has changed since last sync
	metaKey := "content_hash:" + ev.Dir
	lastHash, _ := e.cache.GetMeta(metaKey)
	if lastHash == contentHash {
		return // No change — skip
	}

	// Parse lock file
	pkgs, err := lockfile.Parse(lockPath, ev.Ecosystem)
	if err != nil || len(pkgs) == 0 {
		return
	}

	branch := ""
	commit := ""
	remote := ""
	if gitInfo != nil {
		branch = gitInfo.Branch
		commit = gitInfo.CommitSHA
		remote = gitInfo.RemoteURL
	}

	if !e.online {
		// Queue for later
		_ = e.queue.Enqueue(QueueItem{
			ProjectDir: ev.Dir,
			LockPath:   lockPath,
			Ecosystem:  ev.Ecosystem,
			GitBranch:  branch,
			GitCommit:  commit,
		})
		fmt.Fprintf(os.Stderr, "[sync] offline — queued %s\n", filepath.Base(lockPath))
		return
	}

	// Online sync
	e.syncProject(ev.Dir, lockPath, ev.Ecosystem, branch, commit, remote, contentHash, pkgs, trigger)
}

func (e *Engine) syncProject(projectDir, lockPath, ecosystem, branch, commit, remote, contentHash string, pkgs []lockfile.Package, trigger string) {
	projectHash := hashString(projectDir)
	lockBase := filepath.Base(lockPath)

	// 1. Upsert project
	projectID, err := e.client.UpsertProject(ProjectReq{
		ProjectHash: projectHash,
		PDMCType:    lockBase,
		Path:        projectDir,
		GitRemote:   remote,
		Ecosystem:   ecosystem,
	})
	if err != nil {
		e.handleOffline(projectDir, lockPath, ecosystem, branch, commit, err)
		return
	}

	// 2. Create snapshot with packages
	snapPkgs := make([]SnapshotPkg, len(pkgs))
	for i, p := range pkgs {
		snapPkgs[i] = SnapshotPkg{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: ecosystem,
		}
	}

	_, err = e.client.CreateSnapshot(SnapshotReq{
		ProjectID:   projectID,
		MachineID:   e.machineID,
		ContentHash: contentHash,
		GitBranch:   branch,
		GitCommit:   commit,
		Trigger:     trigger,
		Packages:    snapPkgs,
	})
	if err != nil {
		e.handleOffline(projectDir, lockPath, ecosystem, branch, commit, err)
		return
	}

	// 3. Pull advisories for these packages
	matchPkgs := make([]MatchPkg, len(pkgs))
	for i, p := range pkgs {
		matchPkgs[i] = MatchPkg{Name: p.Name, Ecosystem: ecosystem}
	}

	matchResp, err := e.client.PullAdvisories(MatchReq{Packages: matchPkgs})
	if err != nil {
		// Non-fatal — snapshot was uploaded, advisory pull can retry later
		fmt.Fprintf(os.Stderr, "[sync] advisory pull failed: %v\n", err)
	}

	// 4. Update local cache
	_ = e.cache.ClearProjectAlerts(projectDir)
	if matchResp != nil {
		for _, adv := range matchResp.Advisories {
			_ = e.cache.UpsertProjectAlert(cache.ProjectAlert{
				ProjectDir:  projectDir,
				AdvisoryID:  adv.ID,
				PackageName: adv.PackageName,
				Ecosystem:   adv.Ecosystem,
				Severity:    adv.Severity,
				Summary:     adv.Summary,
			})
		}
	}

	// 5. Update content hash and sync time
	_ = e.cache.SetMeta(metaKey(projectDir), contentHash)
	_ = e.cache.SetMeta("last_full_sync", time.Now().UTC().Format(time.RFC3339))

	alertCount := 0
	if matchResp != nil {
		alertCount = len(matchResp.Advisories)
	}
	fmt.Fprintf(os.Stderr, "[sync] %s → %d pkgs, %d alerts\n",
		filepath.Base(lockPath), len(pkgs), alertCount)
}

func (e *Engine) handleOffline(projectDir, lockPath, ecosystem, branch, commit string, err error) {
	fmt.Fprintf(os.Stderr, "[sync] API error — queueing (%v)\n", err)
	e.online = false
	_ = e.queue.Enqueue(QueueItem{
		ProjectDir: projectDir,
		LockPath:   lockPath,
		Ecosystem:  ecosystem,
		GitBranch:  branch,
		GitCommit:  commit,
	})
}

func (e *Engine) drainQueue() {
	items, err := e.queue.Drain()
	if err != nil || len(items) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "[sync] draining %d queued items\n", len(items))
	for _, item := range items {
		contentHash, err := hashFile(item.LockPath)
		if err != nil {
			continue
		}

		pkgs, err := lockfile.Parse(item.LockPath, item.Ecosystem)
		if err != nil || len(pkgs) == 0 {
			continue
		}

		e.syncProject(item.ProjectDir, item.LockPath, item.Ecosystem,
			item.GitBranch, item.GitCommit, "", contentHash, pkgs, "watcher")
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func metaKey(projectDir string) string {
	return "content_hash:" + projectDir
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h), nil
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// resolveLockPath determines the lock file to parse for a given event path.
// For manifests, returns the adjacent lock file. For lock files, returns the path as-is.
func resolveLockPath(eventPath, ecosystem string) string {
	base := filepath.Base(eventPath)
	dir := filepath.Dir(eventPath)

	// Map manifests to their lock files
	lockFiles := map[string]string{
		"package.json":   "package-lock.json",
		"go.mod":         "go.sum",
		"Cargo.toml":     "Cargo.lock",
		"Gemfile":        "Gemfile.lock",
		"composer.json":  "composer.lock",
		"Pipfile":        "Pipfile.lock",
		"pyproject.toml": "requirements.txt",
	}

	if lockFile, ok := lockFiles[base]; ok {
		candidate := filepath.Join(dir, lockFile)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		// Also check for yarn.lock and pnpm-lock.yaml as npm alternatives
		if ecosystem == "npm" {
			for _, alt := range []string{"yarn.lock", "pnpm-lock.yaml"} {
				candidate = filepath.Join(dir, alt)
				if _, err := os.Stat(candidate); err == nil {
					return candidate
				}
			}
		}
		return "" // No lock file found
	}

	// Already a lock file — return as-is if it exists
	if _, err := os.Stat(eventPath); err == nil {
		return eventPath
	}
	return ""
}
