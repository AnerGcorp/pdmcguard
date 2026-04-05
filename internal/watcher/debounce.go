// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package watcher

import (
	"sync"
	"time"
)

// debouncer collapses rapid events for the same filepath into a single
// emission after the quiet period expires.
type debouncer struct {
	mu      sync.Mutex
	timers  map[string]*time.Timer
	quiet   time.Duration
	onEmit  func(string)
}

func newDebouncer(quiet time.Duration, onEmit func(string)) *debouncer {
	return &debouncer{
		timers: make(map[string]*time.Timer),
		quiet:  quiet,
		onEmit: onEmit,
	}
}

// touch resets the timer for the given path. If no event arrives within the
// quiet period, onEmit is called with the path.
func (d *debouncer) touch(path string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if t, ok := d.timers[path]; ok {
		t.Reset(d.quiet)
		return
	}

	d.timers[path] = time.AfterFunc(d.quiet, func() {
		d.mu.Lock()
		delete(d.timers, path)
		d.mu.Unlock()
		d.onEmit(path)
	})
}

// stop cancels all pending timers.
func (d *debouncer) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.timers {
		t.Stop()
		delete(d.timers, k)
	}
}
