// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package watcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcher_PDMCEvent(t *testing.T) {
	w, err := New(nil) // no exclude store
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	dir := t.TempDir()
	if _, err := w.Add(dir); err != nil {
		t.Fatal(err)
	}

	// Write a PDMC file
	target := filepath.Join(dir, "package.json")
	if err := os.WriteFile(target, []byte(`{"name":"test"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-w.Events:
		if ev.Filename != "package.json" {
			t.Errorf("got filename %q, want package.json", ev.Filename)
		}
		if ev.Ecosystem != "npm" {
			t.Errorf("got ecosystem %q, want npm", ev.Ecosystem)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for PDMC event")
	}
}

func TestWatcher_IgnoresNonPDMC(t *testing.T) {
	w, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	dir := t.TempDir()
	if _, err := w.Add(dir); err != nil {
		t.Fatal(err)
	}

	// Write a non-PDMC file
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("console.log('hi')"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-w.Events:
		t.Errorf("unexpected event for non-PDMC file: %+v", ev)
	case <-time.After(1 * time.Second):
		// Expected — no event
	}
}

func TestWatcher_Debounce(t *testing.T) {
	w, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	dir := t.TempDir()
	if _, err := w.Add(dir); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(dir, "go.mod")

	// Rapid writes — should collapse to a single event
	for i := 0; i < 5; i++ {
		os.WriteFile(target, []byte("module test\n"), 0o644)
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for debounce to fire
	var count int
	timeout := time.After(3 * time.Second)
	drain := time.After(1500 * time.Millisecond) // debounce(500ms) + margin
loop:
	for {
		select {
		case <-w.Events:
			count++
		case <-drain:
			break loop
		case <-timeout:
			break loop
		}
	}

	if count != 1 {
		t.Errorf("expected 1 debounced event, got %d", count)
	}
}
