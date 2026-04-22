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

// BaselineStats is the per-run summary from BaselineScan. Classified
// counts projects where the lockfile content hash changed since last run
// (or was absent), meaning a full classifier roundtrip happened. Skipped
// counts dedup hits — cheap restarts.
type BaselineStats struct {
	Total      int
	Classified int
	Skipped    int
}

// BaselineScan classifies the current lockfile contents of every dir once
// at startup, before the event loop runs, so the shell-hook pre-check is
// accurate on the first cd after daemon start. Without this, a freshly
// installed/restarted daemon stays silent about already-vulnerable
// projects until the user next saves a lockfile — the gap that motivated
// Stage 3.
//
// Relies on HandleChange's content-hash dedup (keyed by dir+ecosystem) so
// subsequent restarts are cheap: only projects whose lockfiles changed
// since the last run do the full classifier roundtrip.
//
// Known limitation: if the daemon starts offline, HandleChange enqueues
// work via handleOffline — but drainQueue only runs once, inside sync.New,
// when initial registration succeeds. Baseline items will sit in queue.db
// until the next online process restart. Pre-existing gap in the sync
// engine, tracked as separate work.
func (e *Engine) BaselineScan(dirs []string, gitReader *git.Reader) BaselineStats {
	var stats BaselineStats
	for _, ev := range watcher.EnumeratePDMCFiles(dirs) {
		stats.Total++

		var gi *git.Info
		if gitReader != nil {
			if info, err := gitReader.Info(ev.Dir); err == nil {
				gi = &info
			}
		}

		// Observe the meta row before/after HandleChange: if the hash
		// changed, we actually did classifier work; if it didn't, dedup
		// short-circuited. This distinguishes "classified" from "skipped"
		// without having to instrument HandleChange itself.
		before, _ := e.cache.GetMeta(metaKey(ev.Dir, ev.Ecosystem))
		e.HandleChange(ev, gi, "baseline")
		after, _ := e.cache.GetMeta(metaKey(ev.Dir, ev.Ecosystem))

		if before != after {
			stats.Classified++
		} else {
			stats.Skipped++
		}
	}

	// Reconcile the shell-hook sentinel against actual DB state. The
	// sentinel (~/.pdmcguard/alerts.flag) is normally written/removed by
	// syncProject's online classifier path — but offline baseline, manual
	// sentinel deletion, or a fresh daemon on a machine with pre-seeded
	// alerts all leave the two out of sync. updateAlertSentinel is a pure
	// function of cache.HasAnyCritical(), so calling it once here makes
	// the on-disk flag match reality regardless of how we got here.
	e.updateAlertSentinel()

	return stats
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

	// Check if content has changed since last sync. Keyed by (dir, ecosystem)
	// so a polyglot project with, say, package.json AND go.mod doesn't let
	// one ecosystem's hash clobber the other's.
	lastHash, _ := e.cache.GetMeta(metaKey(ev.Dir, ev.Ecosystem))
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

	// 4b. Maintain the shell-hook sentinel file. The hook stat()s this
	// before forking the Go binary — keeps prompt latency at zero when
	// there's nothing to warn about on the machine.
	e.updateAlertSentinel()

	// 5. Update content hash and sync time
	_ = e.cache.SetMeta(metaKey(projectDir, ecosystem), contentHash)
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

// AlertSentinelFile returns the path of the file that signals to the shell
// hook whether any critical alerts exist in the local cache.
func AlertSentinelFile() string {
	return config.FilePath("alerts.flag")
}

// updateAlertSentinel writes or removes ~/.pdmcguard/alerts.flag so the
// shell hook can decide without forking whether there is anything worth
// re-checking. Errors are swallowed — a missing or stale sentinel only
// costs one redundant binary invocation; it cannot produce false alerts.
func (e *Engine) updateAlertSentinel() {
	path := AlertSentinelFile()
	hasAny, err := e.cache.HasAnyCritical()
	if err != nil {
		return
	}
	if hasAny {
		_ = os.WriteFile(path, []byte(""), 0o644)
		return
	}
	_ = os.Remove(path)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// metaKey namespaces the content-hash meta row by ecosystem so two PDMC
// files living in the same dir (package.json + go.mod, Cargo.toml + go.mod,
// etc.) each track their own hash. Pre-Stage-3 this was keyed by dir alone
// and the second write clobbered the first's hash, causing unnecessary
// re-classifies on every event for polyglot projects.
func metaKey(projectDir, ecosystem string) string {
	return "content_hash:" + ecosystem + ":" + projectDir
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
