// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AnerGcorp/pdmcguard/internal/bootstrap"
	"github.com/AnerGcorp/pdmcguard/internal/cache"
	"github.com/AnerGcorp/pdmcguard/internal/classifier"
	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/daemon"
	"github.com/AnerGcorp/pdmcguard/internal/excludes"
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

		case "exclude":
			cmdExclude(filteredArgs[1:])
			return

		case "unexclude":
			cmdUnexclude(filteredArgs[1:])
			return

		case "track":
			cmdTrack(filteredArgs[1:])
			return

		case "untrack":
			// CLI alias for `exclude`. The symmetric verb pair is the
			// primary discoverability win; a genuine runtime-only untrack
			// would self-heal on the next rescan, confusing users.
			cmdExclude(filteredArgs[1:])
			return

		case "doctor":
			cmdDoctor(filteredArgs[1:])
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

	// Load user-facing path exclusions (~/.pdmcguard/excludes plus the
	// hardcoded Defaults list). Missing file is fine — the file is
	// created lazily by `pdmcguard exclude`. Matcher is passed to both
	// bootstrap.Scan and watcher.New so rules take effect at both the
	// initial walk and the live event loop; mtime-based hot reload
	// picks up `pdmcguard exclude` without restart.
	matcher, err := excludes.Load(config.FilePath("excludes"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load excludes: %v\n", err)
		os.Exit(1)
	}

	// Bootstrap: scan for project directories
	roots := bootstrap.DefaultRoots()
	roots = append(roots, extraRoots...)
	fmt.Printf("Scanning roots: %v\n", roots)

	dirs, err := bootstrap.Scan(store, matcher, roots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: bootstrap scan: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d project directories\n", len(dirs))
	for _, d := range dirs {
		fmt.Printf("  %s\n", d)
	}

	// Start watcher
	w, err := watcher.New(store, matcher)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create watcher: %v\n", err)
		os.Exit(1)
	}
	defer w.Close()

	// trackedDirs is the authoritative set of project directories the
	// daemon is watching and has classified at least once. Written only
	// from this goroutine's select loop (below) so no mutex is needed —
	// producer goroutines send paths on newDirs, we dedup here.
	trackedDirs := make(map[string]bool, len(dirs))

	for _, d := range dirs {
		added, err := w.Add(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: watch %s: %v\n", d, err)
			continue
		}
		if !added {
			fmt.Printf("  skipped (excluded): %s\n", d)
			continue
		}
		trackedDirs[d] = true
	}

	// Register each scan root for runtime-discovery fast-path: Create
	// events for new children under roots flow back via w.RootCreates.
	// Failure here is not fatal — the periodic rescan (below) still
	// converges. Roots aren't de-duplicated against `dirs` because
	// watching the same inode twice in fsnotify is a no-op.
	for _, root := range roots {
		if err := w.WatchRoot(root); err != nil {
			fmt.Fprintf(os.Stderr, "warning: watch root %s: %v\n", root, err)
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

	// newDirs carries runtime-discovered project directories to the main
	// select below. Two producer goroutines feed it: the fast path
	// consuming w.RootCreates, and the periodic rescan ticker.
	newDirs := make(chan string, 32)

	// Producer A — fast path. For every new child of a watched root,
	// shallow-scan via bootstrap.ScanOne and forward any PDMC-bearing
	// subdirs. ScanOne is the same exclusion-aware walker used at startup,
	// so `node_modules`, user excludes, classifier fingerprints, and
	// hidden dirs are all filtered before we touch newDirs.
	go func() {
		for created := range w.RootCreates {
			found, err := bootstrap.ScanOne(store, matcher, created)
			if err != nil {
				continue
			}
			for _, d := range found {
				select {
				case newDirs <- d:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Producer C — explicit IPC. `pdmcguard track <path>` dials the
	// daemon's Unix-domain socket and enqueues a path for tracking
	// immediately, independent of the fsnotify fast path and the
	// periodic rescan. Handler runs ScanOne (same exclusion-aware
	// walker) and forwards hits onto newDirs so dedup + w.Add +
	// BaselineScan happen on the main select goroutine — no new shared
	// state. Listener lifetime is tied to ctx; a bind failure logs and
	// the daemon keeps running without the IPC surface.
	ipcHandler := func(_ context.Context, req daemon.Request) daemon.Response {
		switch req.Op {
		case "track":
			if req.Path == "" {
				return daemon.Response{Error: "track: path is required"}
			}
			abs, err := filepath.Abs(req.Path)
			if err != nil {
				return daemon.Response{Error: fmt.Sprintf("track: %v", err)}
			}
			if resolved, err := filepath.EvalSymlinks(abs); err == nil {
				abs = resolved
			}
			abs = filepath.Clean(abs)
			if info, err := os.Stat(abs); err != nil || !info.IsDir() {
				return daemon.Response{Error: fmt.Sprintf("track: %s: not a directory", abs)}
			}
			found, err := bootstrap.ScanOne(store, matcher, abs)
			if err != nil {
				return daemon.Response{Error: fmt.Sprintf("track: scan: %v", err)}
			}
			for _, d := range found {
				select {
				case newDirs <- d:
				case <-ctx.Done():
					return daemon.Response{Error: "daemon shutting down"}
				}
			}
			msg := fmt.Sprintf("queued %d project(s) under %s", len(found), abs)
			if len(found) == 0 {
				msg = fmt.Sprintf("no PDMC files under %s", abs)
			}
			return daemon.Response{OK: true, Found: len(found), Message: msg}
		default:
			return daemon.Response{Error: fmt.Sprintf("unknown op %q", req.Op)}
		}
	}
	go func() {
		if err := daemon.Listen(ctx, daemon.SocketPath(), ipcHandler); err != nil {
			fmt.Fprintf(os.Stderr, "warning: ipc listener: %v\n", err)
		}
	}()

	// Producer B — safety net. A low-frequency full rescan picks up
	// edges fsnotify loses under burst load (huge `git clone`), atomic
	// renames, and tools that write files into dirs we never got a
	// Create event for. Default 5m; PDMCGUARD_RESCAN_INTERVAL=<dur>
	// overrides (0 disables). Already-tracked dirs are filtered by the
	// consumer, and BaselineScan's content-hash dedup makes reclassifying
	// unchanged lockfiles a cheap local lookup.
	rescanEvery := parseRescanInterval(os.Getenv("PDMCGUARD_RESCAN_INTERVAL"), 5*time.Minute)
	if rescanEvery > 0 {
		go func() {
			t := time.NewTicker(rescanEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					for _, root := range roots {
						found, err := bootstrap.ScanOne(store, matcher, root)
						if err != nil {
							continue
						}
						for _, d := range found {
							select {
							case newDirs <- d:
							case <-ctx.Done():
								return
							}
						}
					}
				}
			}
		}()
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
		case d := <-newDirs:
			// Runtime-discovered project: skip if already tracked, else
			// watch it, mark tracked, and run a one-shot baseline so any
			// existing advisories surface immediately (pre-check is
			// accurate on the first cd into the new repo).
			if trackedDirs[d] {
				continue
			}
			added, addErr := w.Add(d)
			if addErr != nil {
				fmt.Fprintf(os.Stderr, "warning: watch %s: %v\n", d, addErr)
				continue
			}
			if !added {
				continue
			}
			trackedDirs[d] = true
			fmt.Printf("[discovered] %s\n", d)
			syncEngine.BaselineScan([]string{d}, gitReader)
		case err := <-w.Errors:
			fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		case <-sig:
			fmt.Println("\nShutting down...")
			cancel() // Stop SSE listener + producer goroutines
			return
		}
	}
}

// parseRescanInterval parses the PDMCGUARD_RESCAN_INTERVAL env-var value.
// Accepts Go duration syntax ("5m", "30s") plus the literal "0" / "off" /
// "false" as a disable. Unparseable values fall back to def with a stderr
// note so the user notices a typo instead of silently getting the default.
func parseRescanInterval(raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	switch raw {
	case "0", "off", "false":
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: PDMCGUARD_RESCAN_INTERVAL=%q not a duration; using default %s\n", raw, def)
		return def
	}
	return d
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

	// IPC socket — stat-only check. Status stays fast and never hangs
	// on a pathological socket; `pdmcguard doctor` is where liveness is
	// actually verified with a dial.
	if _, err := os.Stat(daemon.SocketPath()); err == nil {
		fmt.Printf("IPC:         listening at %s\n", daemon.SocketPath())
	} else {
		fmt.Println("IPC:         daemon not running")
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
  pdmcguard exclude <path>  Skip a path or basename from scans (--list to show rules)
  pdmcguard unexclude <path>  Remove a previously-added exclusion rule
  pdmcguard track [path]    Register a path with the running daemon (default: cwd)
  pdmcguard untrack <path>  Alias for 'exclude' — stop tracking a path
  pdmcguard doctor          Run a health check across install, cache, and config
  pdmcguard version         Print version information

Flags:
  --root DIR                Add a custom scan root (repeatable)
  -h, --help                Show this help message
  -v, --version             Print version`)
}
