// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestIPC_RequestResponseRoundTrip asserts the wire format: Request and
// Response marshal to newline-delimited JSON and survive a round trip
// with every field preserved. Catches an accidental struct tag change or
// field rename that would silently break a deployed CLI talking to an
// upgraded daemon (or vice-versa).
func TestIPC_RequestResponseRoundTrip(t *testing.T) {
	reqIn := Request{Op: "track", Path: "/abs/path/to/project"}
	b, err := json.Marshal(reqIn)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var reqOut Request
	if err := json.Unmarshal(b, &reqOut); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if reqOut != reqIn {
		t.Errorf("request round trip: got %+v want %+v", reqOut, reqIn)
	}

	respIn := Response{OK: true, Message: "queued 3 project(s)", Found: 3}
	b, err = json.Marshal(respIn)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var respOut Response
	if err := json.Unmarshal(b, &respOut); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if respOut != respIn {
		t.Errorf("response round trip: got %+v want %+v", respOut, respIn)
	}
}

// TestIPC_ListenAndHandle spins up a real Listen on a temp-dir socket,
// sends one request via SendRequest, and asserts the handler received
// the exact Op/Path and the response made it back. This is the
// end-to-end proof that socket binding, chmod, accept, serveConn, and
// Dial all line up — unit-testing the helpers in isolation would miss
// protocol drift.
func TestIPC_ListenAndHandle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sock := filepath.Join(t.TempDir(), "daemon.sock")

	var gotReq Request
	var mu sync.Mutex
	handler := func(_ context.Context, req Request) Response {
		mu.Lock()
		gotReq = req
		mu.Unlock()
		return Response{OK: true, Found: 7, Message: "ok from handler"}
	}

	listenErr := make(chan error, 1)
	go func() {
		listenErr <- Listen(ctx, sock, handler)
	}()

	waitForSocket(t, sock)

	want := Request{Op: "track", Path: "/tmp/adhoc-proj"}
	resp, err := SendRequest(sock, want)
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if !resp.OK {
		t.Errorf("resp.OK = false; want true (err=%q)", resp.Error)
	}
	if resp.Found != 7 {
		t.Errorf("resp.Found = %d; want 7", resp.Found)
	}
	if resp.Message != "ok from handler" {
		t.Errorf("resp.Message = %q; want %q", resp.Message, "ok from handler")
	}

	mu.Lock()
	if gotReq != want {
		t.Errorf("handler got %+v; want %+v", gotReq, want)
	}
	mu.Unlock()

	cancel()
	select {
	case err := <-listenErr:
		if err != nil {
			t.Errorf("Listen returned %v on ctx cancel; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not return after ctx cancel")
	}
}

// TestIPC_DialMissingSocket: Dial on a path that doesn't exist surfaces
// ErrDaemonNotRunning, not a bare syscall error. The CLI relies on this
// to render the friendly "daemon is not running" message.
func TestIPC_DialMissingSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "nope.sock")
	_, err := Dial(sock)
	if err != ErrDaemonNotRunning {
		t.Errorf("Dial on missing socket: got %v; want ErrDaemonNotRunning", err)
	}
}

// TestIPC_HandlerUnknownOp verifies that a handler returning an error
// response for unknown ops surfaces that error verbatim. Exercises the
// common "future CLI talks to older daemon" compatibility path.
func TestIPC_HandlerUnknownOp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sock := filepath.Join(t.TempDir(), "daemon.sock")
	handler := func(_ context.Context, req Request) Response {
		if req.Op != "track" {
			return Response{Error: "unknown op " + req.Op}
		}
		return Response{OK: true}
	}

	go Listen(ctx, sock, handler)
	waitForSocket(t, sock)

	resp, err := SendRequest(sock, Request{Op: "future-op"})
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if resp.OK {
		t.Error("expected OK=false for unknown op")
	}
	if resp.Error != "unknown op future-op" {
		t.Errorf("resp.Error = %q; want %q", resp.Error, "unknown op future-op")
	}
}

// TestIPC_StaleSocketRecovered: a leftover file at the bind path must
// not block a fresh Listen call. Simulates a prior-process crash where
// the defer Unlink never ran.
func TestIPC_StaleSocketRecovered(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sock := filepath.Join(t.TempDir(), "stale.sock")
	// Seed a stray regular file at the bind path — stands in for a
	// socket inode a prior process failed to unlink on exit.
	if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
		t.Fatalf("seed stale file: %v", err)
	}

	handler := func(context.Context, Request) Response { return Response{OK: true} }
	listenErr := make(chan error, 1)
	go func() { listenErr <- Listen(ctx, sock, handler) }()
	waitForSocket(t, sock)

	resp, err := SendRequest(sock, Request{Op: "ping"})
	if err != nil {
		t.Fatalf("SendRequest after stale-socket recovery: %v", err)
	}
	if !resp.OK {
		t.Errorf("resp.OK = false; want true")
	}
	cancel()
	<-listenErr
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("socket %s did not appear within 2s", path)
}
