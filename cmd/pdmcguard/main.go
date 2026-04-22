// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AnerGcorp/pdmcguard/internal/bootstrap"
	"github.com/AnerGcorp/pdmcguard/internal/cache"
	"github.com/AnerGcorp/pdmcguard/internal/classifier"
	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/daemon"
	"github.com/AnerGcorp/pdmcguard/internal/git"
	"github.com/AnerGcorp/pdmcguard/internal/notify"
	"github.com/AnerGcorp/pdmcguard/internal/sync"
	"github.com/AnerGcorp/pdmcguard/internal/watcher"
)

// Set by -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Collect --root flags for custom scan roots (before command parsing)
	// and the --no-baseline flag that skips the Stage 3 startup baseline
	// pass. Flags are stripped from filteredArgs so the subcommand switch
	// below still sees the command as arg[0].
	var extraRoots []string
	var noBaseline bool
	var filteredArgs []string
	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--root" && i+1 < len(os.Args):
			extraRoots = append(extraRoots, os.Args[i+1])
			i++
		case os.Args[i] == "--no-baseline":
			noBaseline = true
		default:
			filteredArgs = append(filteredArgs, os.Args[i])
		}
	}

	if len(filteredArgs) > 0 {
		switch filteredArgs[0] {
		case "version", "--version", "-v":
			fmt.Printf("pdmcguard %s (commit: %s, built: %s)\n", version, commit, date)
			return

		case "status":
			cmdStatus()
			return

		case "install":
			cmdInstall(filteredArgs[1:])
			return

		case "uninstall":
			cmdUninstall(filteredArgs[1:])
			return

		case "login":
			cmdLogin(filteredArgs[1:])
			return

		case "pre-check":
			os.Exit(cmdPreCheck())

		case "hook-init":
			cmdHookInit(filteredArgs[1:])
			return

		case "ack":
			cmdAck(filteredArgs[1:])
			return

		case "unack":
			cmdUnack(filteredArgs[1:])
			return

		case "help", "--help", "-h":
			printUsage()
			return

		default:
			fmt.Fprintf(os.Stderr, "pdmcguard: unknown command %q\n", filteredArgs[0])
			printUsage()
			os.Exit(1)
		}
	}

	// Default: run as daemon
	runDaemon(extraRoots, noBaseline)
}

func runDaemon(extraRoots []string, noBaseline bool) {
	fmt.Printf("pdmcguard %s starting...\n", version)
	fmt.Printf("Config dir: %s\n", config.Dir())

	// Open exclude store
	store, err := classifier.OpenExcludeStore(config.FilePath("excludes.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open exclude store: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	// Bootstrap: scan for project directories
	roots := bootstrap.DefaultRoots()
	roots = append(roots, extraRoots...)
	fmt.Printf("Scanning roots: %v\n", roots)

	dirs, err := bootstrap.Scan(store, roots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: bootstrap scan: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d project directories\n", len(dirs))
	for _, d := range dirs {
		fmt.Printf("  %s\n", d)
	}

	// Start watcher
	w, err := watcher.New(store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create watcher: %v\n", err)
		os.Exit(1)
	}
	defer w.Close()

	for _, d := range dirs {
		added, err := w.Add(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: watch %s: %v\n", d, err)
			continue
		}
		if !added {
			fmt.Printf("  skipped (excluded): %s\n", d)
		}
	}

	// Git reader for enriching events with branch/commit metadata
	gitReader := git.NewReader()

	// Open cache and sync engine
	cacheStore, err := cache.Open(config.FilePath("cache.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open cache: %v\n", err)
		os.Exit(1)
	}
	defer cacheStore.Close()

	syncEngine, err := sync.New(cacheStore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: init sync engine: %v\n", err)
		os.Exit(1)
	}
	defer syncEngine.Close()

	// Start SSE listener for desktop notifications (if online)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Background reconnect-and-drain loop. Picks up mid-session `pdmcguard
	// login` within ~reconnectInterval and retries the API after transient
	// failures so offline-queued work doesn't wait for a process restart.
	syncEngine.Start(ctx)

	if syncEngine.Online() {
		creds, credErr := sync.LoadCredentials()
		if credErr == nil {
			sseListener := notify.NewSSEListener(creds.APIURL, creds.AccessToken)
			go sseListener.Run(ctx)
		}
	}

	// Baseline scan: classify every tracked project once before entering the
	// event loop so the shell-hook pre-check is accurate on the very first
	// cd after daemon start. HandleChange's content-hash dedup (keyed by
	// dir+ecosystem) makes this cheap on subsequent restarts — only
	// projects whose lockfiles actually changed since last run do the full
	// classifier roundtrip.
	//
	// Opt-out via --no-baseline flag or PDMCGUARD_BASELINE=0/false env var
	// (either disables). Ships on day one because slow startup is the exact
	// symptom users should self-diagnose without waiting for a release.
	envVal := os.Getenv("PDMCGUARD_BASELINE")
	baselineOff := noBaseline || envVal == "0" || envVal == "false"
	if !baselineOff {
		fmt.Println("Running baseline scan...")
		stats := syncEngine.BaselineScan(dirs, gitReader)
		fmt.Printf("Baseline: %d projects (%d classified, %d unchanged)\n",
			stats.Total, stats.Classified, stats.Skipped)
	}

	fmt.Println("Watching for PDMC file changes... (Ctrl+C to stop)")

	// Handle signals for clean shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case ev := <-w.Events:
			info, gitErr := gitReader.Info(ev.Dir)
			var gitInfo *git.Info
			if gitErr == nil {
				gitInfo = &info
				fmt.Printf("[change] %s (%s) branch=%s commit=%.8s\n",
					ev.Path, ev.Ecosystem, info.Branch, info.CommitSHA)
			} else {
				fmt.Printf("[change] %s (%s)\n", ev.Path, ev.Ecosystem)
			}
			syncEngine.HandleChange(ev, gitInfo, "watcher")
		case err := <-w.Errors:
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		case <-sig:
			fmt.Println("\nShutting down...")
			cancel() // Stop SSE listener
			return
		}
	}
}

func cmdStatus() {
	fmt.Printf("pdmcguard %s\n", version)
	fmt.Printf("Config dir:  %s\n", config.Dir())

	// Check service status
	svc := daemon.NewServiceManager()
	if svc.IsInstalled() {
		fmt.Println("Service:     installed")
	} else {
		fmt.Println("Service:     not installed (run 'pdmcguard install')")
	}

	// Check credentials
	_, credErr := sync.LoadCredentials()
	if credErr != nil {
		fmt.Println("Sync mode:   offline (run 'pdmcguard login')")
	} else {
		fmt.Println("Sync mode:   online")
	}

	// Show cache info
	cacheStore, err := cache.Open(config.FilePath("cache.db"))
	if err == nil {
		defer cacheStore.Close()
		lastSync, _ := cacheStore.GetMeta("last_full_sync")
		if lastSync != "" {
			fmt.Printf("Last sync:   %s\n", lastSync)
		} else {
			fmt.Println("Last sync:   never")
		}
	}

	// Show queue depth
	q, err := sync.OpenQueue(config.FilePath("queue.db"))
	if err == nil {
		defer q.Close()
		n, _ := q.Len()
		if n > 0 {
			fmt.Printf("Queue:       %d pending items\n", n)
		} else {
			fmt.Println("Queue:       empty")
		}
	}
}

func printUsage() {
	fmt.Println(`PDMCGuard — Passive Dependency Monitor & Compromise Guard

Usage:
  pdmcguard [--root DIR]    Run as background daemon
  pdmcguard install         Install daemon, shell hooks, and system service
  pdmcguard uninstall       Remove system service and shell hooks (--purge to remove data)
  pdmcguard login           Authenticate with PDMCGuard cloud (--api-url for self-hosted)
  pdmcguard status          Show daemon status, sync mode, and queue depth
  pdmcguard pre-check       Check current project for critical advisories (used by shell hook)
  pdmcguard hook-init       Output shell hook snippet (eval "$(pdmcguard hook-init)")
  pdmcguard ack <id>        Permanently dismiss an advisory (--all-projects for global, --list to show)
  pdmcguard unack <id>      Reverse a prior ack (--all-projects for global)
  pdmcguard version         Print version information

Flags:
  --root DIR                Add a custom scan root (repeatable)
  -h, --help                Show this help message
  -v, --version             Print version`)
}
