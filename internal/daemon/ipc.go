// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/AnerGcorp/pdmcguard/internal/config"
)

// Request is the wire format for one IPC call. Op enumerates the daemon
// action; future ops (e.g. "reload", "status") can be added without breaking
// existing clients — unknown ops get a typed error response.
type Request struct {
	Op   string `json:"op"`
	Path string `json:"path,omitempty"`
}

// Response is the wire format for the daemon's reply. Exactly one of
// {OK:true} or {OK:false,Error:...} is meaningful per reply. Found is the
// count of PDMC-bearing subdirs surfaced by a track op, for user feedback.
type Response struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Found   int    `json:"found,omitempty"`
}

// Handler is the daemon-side callback invoked for each request. The
// implementation mutates whatever state the op requires (e.g. enqueue onto
// newDirs in runDaemon) and returns the response to send back. Handler
// MUST NOT panic on malformed ops — return Response{Error: "..."} instead.
type Handler func(ctx context.Context, req Request) Response

// ipcConnDeadline caps how long a single request/response exchange can
// hold a server goroutine. Generous enough for a ScanOne over a large
// workspace yet short enough to unblock a pathological client.
const ipcConnDeadline = 30 * time.Second

// ipcDialTimeout is used by Dial and by doctor's liveness check. One
// second is plenty for a local socket; longer suggests the daemon is
// hung, which is information the caller wants immediately.
const ipcDialTimeout = 1 * time.Second

// ErrDaemonNotRunning is returned by Dial when the socket is missing or
// refuses connections. The CLI surfaces it with a user-facing "daemon is
// not running" message rather than the bare syscall error.
var ErrDaemonNotRunning = errors.New("pdmcguard daemon is not running")

// SocketPath is the canonical Unix-domain socket location inside the
// config dir. Kept in this package so the CLI and daemon agree on one
// source of truth without importing each other.
func SocketPath() string {
	return config.FilePath("daemon.sock")
}

// Listen binds a Unix-domain socket at path, chmods it 0600, and serves
// newline-delimited JSON requests until ctx is cancelled. Each accepted
// connection is one-shot: read a Request, invoke handler, write a
// Response, close. Stale socket files are unlinked before bind to
// recover from unclean previous exits.
//
// Errors from Accept are logged to stderr and the loop continues;
// ctx.Done triggers a clean close and socket unlink. Returns nil on
// graceful shutdown, non-nil only if the initial bind fails.
func Listen(ctx context.Context, path string, handler Handler) error {
	// Unlink any leftover socket from a prior crash. ENOENT is expected
	// on a clean start and silently ignored; other errors (permission,
	// stale directory) propagate out of the subsequent Listen call.
	_ = syscall.Unlink(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("bind %s: %w", path, err)
	}
	// Best-effort chmod. Unix domain sockets honor file perms on macOS
	// and Linux; other users on the box can't connect at 0600.
	_ = os.Chmod(path, 0o600)

	// Clean up both the listener and the socket file on shutdown. The
	// explicit Unlink is hygiene — next start would unlink anyway, but
	// leaving stale sockets around is noisy in ~/.pdmcguard.
	go func() {
		<-ctx.Done()
		ln.Close()
		_ = syscall.Unlink(path)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener was closed via the ctx goroutine — clean exit.
			if ctx.Err() != nil {
				return nil
			}
			// Transient accept error (EMFILE, ECONNABORTED, …). Log
			// and keep serving; giving up on a single bad connection
			// would take the IPC surface down for good.
			fmt.Fprintf(os.Stderr, "ipc accept: %v\n", err)
			continue
		}
		go serveConn(ctx, conn, handler)
	}
}

// serveConn reads one request, dispatches it, writes one response, and
// closes. Deadlines ensure a misbehaving client can't pin the goroutine.
func serveConn(ctx context.Context, conn net.Conn, handler Handler) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ipcConnDeadline))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		writeResponse(conn, Response{Error: fmt.Sprintf("read: %v", err)})
		return
	}
	// Accept payloads without a trailing newline too (e.g. `nc -U`
	// sending then closing stdin). ReadBytes returns what it has plus
	// io.EOF in that case, which the check above already tolerates.
	if len(line) == 0 {
		writeResponse(conn, Response{Error: "empty request"})
		return
	}

	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeResponse(conn, Response{Error: fmt.Sprintf("parse: %v", err)})
		return
	}
	resp := handler(ctx, req)
	writeResponse(conn, resp)
}

func writeResponse(w io.Writer, resp Response) {
	b, err := json.Marshal(resp)
	if err != nil {
		// Impossibly rare — Response fields are all primitives. Best we
		// can do is emit a plain error and let the client parse-fail.
		fmt.Fprintf(w, `{"ok":false,"error":"encode: %s"}`+"\n", err)
		return
	}
	b = append(b, '\n')
	_, _ = w.Write(b)
}

// Dial opens a connection to the daemon IPC socket. Returns
// ErrDaemonNotRunning when the socket is missing or refuses connections
// so the CLI can render a friendly message instead of the bare syscall
// error. Any other error propagates as-is.
func Dial(path string) (net.Conn, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrDaemonNotRunning
		}
		return nil, err
	}
	conn, err := net.DialTimeout("unix", path, ipcDialTimeout)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, ErrDaemonNotRunning
		}
		return nil, err
	}
	return conn, nil
}

// SendRequest dials, writes req, reads one Response, closes. Convenience
// for one-shot CLI callers; server-side handlers use the low-level
// encode/decode directly in serveConn.
func SendRequest(path string, req Request) (Response, error) {
	conn, err := Dial(path)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ipcConnDeadline))

	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("encode request: %w", err)
	}
	b = append(b, '\n')
	if _, err := conn.Write(b); err != nil {
		return Response{}, fmt.Errorf("write request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("decode response: %w", err)
	}
	return resp, nil
}
