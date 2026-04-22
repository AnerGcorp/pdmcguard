// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package watcher provides OS-level file watching for PDMC files.
package watcher

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AnerGcorp/pdmcguard/internal/classifier"
	"github.com/AnerGcorp/pdmcguard/internal/excludes"
	"github.com/fsnotify/fsnotify"
)

const debounceQuiet = 500 * time.Millisecond

// PDMCChangeEvent represents a change to a dependency file.
type PDMCChangeEvent struct {
	Path      string // absolute path to the changed file
	Dir       string // parent directory
	Filename  string // base filename (e.g. "go.mod")
	Ecosystem string // ecosystem key from PDMCFiles
}

// Watcher watches project directories for PDMC file changes.
//
// RootCreates emits the absolute path of every new, non-hidden direct child
// of a directory registered via WatchRoot. It is the fast-path discovery
// signal for `runDaemon`: when a user `git clone`s into `~/Projects/`, the
// daemon sees the new directory here without waiting for a full rescan.
// The channel is buffered; if a producer can't enqueue (consumer slow or
// absent) the event is dropped on the floor rather than blocking the
// fsnotify loop — the periodic rescan is the safety net for dropped sends.
type Watcher struct {
	Events      chan PDMCChangeEvent
	Errors      chan error
	RootCreates chan string

	fsw     *fsnotify.Watcher
	store   *classifier.ExcludeStore
	matcher *excludes.Matcher
	deb     *debouncer
	done    chan struct{}

	rootMu  sync.RWMutex
	rootSet map[string]bool
}

// New creates a Watcher backed by fsnotify. The ExcludeStore is used to skip
// excluded directories when Add is called. The matcher (may be nil) enforces
// user-facing path-based exclusions both at Add time and inside the event
// loop — the latter is defensive so a rule added after a directory is
// already being watched silences pending events without requiring a daemon
// restart.
func New(store *classifier.ExcludeStore, matcher *excludes.Matcher) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		Events:      make(chan PDMCChangeEvent, 64),
		Errors:      make(chan error, 8),
		RootCreates: make(chan string, 32),
		fsw:         fsw,
		store:       store,
		matcher:     matcher,
		done:        make(chan struct{}),
		rootSet:     make(map[string]bool),
	}

	w.deb = newDebouncer(debounceQuiet, func(path string) {
		// Re-check matcher at debounce-fire time. MaybeReload inside
		// Matches means a `pdmcguard exclude` issued between the
		// fsnotify event and the debounce fire still takes effect.
		if w.matcher != nil && w.matcher.Matches(path) {
			return
		}
		base := filepath.Base(path)
		eco, ok := PDMCFiles[base]
		if !ok {
			return
		}
		w.Events <- PDMCChangeEvent{
			Path:      path,
			Dir:       filepath.Dir(path),
			Filename:  base,
			Ecosystem: eco,
		}
	})

	go w.loop()
	return w, nil
}

// WatchRoot registers root as a discovery root. fsnotify Create events for
// direct (non-hidden) children of root are forwarded on RootCreates so the
// daemon can pick up newly-cloned projects without a full rescan.
//
// An already-registered root is a no-op. fsnotify.Add errors propagate.
// The root is also added to the fsnotify watch set, but file-level events
// inside it still flow through the normal PDMC pipeline — WatchRoot is
// additive to the existing Add path, not a replacement.
func (w *Watcher) WatchRoot(root string) error {
	root = filepath.Clean(root)
	w.rootMu.Lock()
	already := w.rootSet[root]
	if !already {
		w.rootSet[root] = true
	}
	w.rootMu.Unlock()
	if already {
		return nil
	}
	if err := w.fsw.Add(root); err != nil {
		w.rootMu.Lock()
		delete(w.rootSet, root)
		w.rootMu.Unlock()
		return err
	}
	return nil
}

// isRoot reports whether dir is a registered discovery root. Held under an
// RLock so concurrent WatchRoot calls don't block the hot path.
func (w *Watcher) isRoot(dir string) bool {
	w.rootMu.RLock()
	defer w.rootMu.RUnlock()
	return w.rootSet[dir]
}

// Add starts watching a directory for PDMC file changes.
// Returns false (without error) if the directory is excluded — either by
// a user path rule (consulted first, cheap in-memory match) or an inode
// entry in the store.
func (w *Watcher) Add(dir string) (bool, error) {
	if w.matcher != nil && w.matcher.Matches(dir) {
		return false, nil
	}
	if w.store != nil {
		inode, err := classifier.InodeOf(dir)
		if err == nil && w.store.IsExcluded(inode) {
			return false, nil
		}
	}
	if err := w.fsw.Add(dir); err != nil {
		return false, err
	}
	return true, nil
}

// Close shuts down the watcher and releases resources.
func (w *Watcher) Close() error {
	w.deb.stop()
	err := w.fsw.Close()
	<-w.done
	return err
}

func (w *Watcher) loop() {
	// Close RootCreates on exit so consumers that range over it can
	// terminate cleanly when the watcher is shut down.
	defer close(w.RootCreates)
	defer close(w.done)
	for {
		select {
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			// Only care about Write and Create operations
			if ev.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			// Root-watch fast path: Create events for a non-hidden direct
			// child of a registered root are forwarded on RootCreates
			// regardless of whether the new entry is itself a PDMC file.
			// The consumer decides (via bootstrap.ScanOne) whether the
			// subtree is interesting — keeps watcher free of filesystem
			// walks. We best-effort stat the path so a plain file Create
			// (e.g. `touch ~/Projects/README`) doesn't wake the consumer,
			// but if the stat races with a rename we emit anyway and let
			// ScanOne drop it cheaply.
			if ev.Op&fsnotify.Create != 0 {
				parent := filepath.Dir(ev.Name)
				if w.isRoot(parent) {
					name := filepath.Base(ev.Name)
					if !strings.HasPrefix(name, ".") {
						if fi, statErr := os.Lstat(ev.Name); statErr != nil || fi.IsDir() {
							select {
							case w.RootCreates <- ev.Name:
							default:
								// Channel full — periodic rescan is the safety net.
							}
						}
					}
				}
			}

			base := filepath.Base(ev.Name)
			if !IsPDMC(base) {
				continue
			}
			// Defensive: drop events under an excluded path even if we
			// somehow started watching it. Covers the race where a user
			// runs `pdmcguard exclude` after the watcher registered the
			// directory — the file-level event is suppressed immediately
			// without waiting for a daemon restart.
			if w.matcher != nil && w.matcher.Matches(ev.Name) {
				continue
			}
			w.deb.touch(ev.Name)

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			w.Errors <- err
		}
	}
}
