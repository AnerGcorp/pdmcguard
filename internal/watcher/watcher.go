// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package watcher provides OS-level file watching for PDMC files.
package watcher

import (
	"path/filepath"
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
type Watcher struct {
	Events chan PDMCChangeEvent
	Errors chan error

	fsw      *fsnotify.Watcher
	store    *classifier.ExcludeStore
	matcher  *excludes.Matcher
	deb      *debouncer
	done     chan struct{}
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
		Events:  make(chan PDMCChangeEvent, 64),
		Errors:  make(chan error, 8),
		fsw:     fsw,
		store:   store,
		matcher: matcher,
		done:    make(chan struct{}),
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
