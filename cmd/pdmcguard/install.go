// PDMCGuard — Passive Dependency Monitor & Compromise Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/AnerGcorp/pdmcguard/internal/config"
	"github.com/AnerGcorp/pdmcguard/internal/daemon"
)

func cmdInstall(args []string) {
	noService := false
	noHook := false
	for _, a := range args {
		switch a {
		case "--no-service":
			noService = true
		case "--no-hook":
			noHook = true
		}
	}

	// 1. Resolve current binary
	srcBin, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot resolve binary path: %v\n", err)
		os.Exit(1)
	}
	srcBin, _ = filepath.EvalSymlinks(srcBin)

	// Pre-flight: refuse to publish a corrupt source. A bad `go build -o`
	// can silently produce a 0-byte file, a partial scp leaves a non-exec
	// artifact — either way, copying it would brick the install while
	// reporting success. Size + exec bit catches both without the cost of
	// subprocessing the source (hangs, timeouts, process-tree surprises).
	if err := verifyBinary(srcBin); err != nil {
		fmt.Fprintf(os.Stderr, "error: source binary is corrupt: %v\n", err)
		os.Exit(1)
	}

	// 2. Copy binary to ~/.pdmcguard/bin/pdmcguard
	destDir := filepath.Join(config.Dir(), "bin")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: create bin dir: %v\n", err)
		os.Exit(1)
	}
	destBin := filepath.Join(destDir, "pdmcguard")

	if err := copyFile(srcBin, destBin); err != nil {
		fmt.Fprintf(os.Stderr, "error: copy binary: %v\n", err)
		os.Exit(1)
	}
	if err := os.Chmod(destBin, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: chmod binary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Binary installed: %s\n", destBin)

	// 3. Register system service
	if !noService {
		svc := daemon.NewServiceManager()
		if svc.IsInstalled() {
			// Stop and reinstall to pick up new binary
			_ = svc.Stop()
			_ = svc.Uninstall()
		}
		if err := svc.Install(destBin); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: service registration failed: %v\n", err)
			fmt.Fprintln(os.Stderr, "  You can run the daemon manually: pdmcguard")
		} else {
			fmt.Println("  System service registered and started")
		}
	}

	// 4. Inject shell hook
	if !noHook {
		shell := daemon.DetectShell()
		if err := daemon.InjectHook(shell, destBin); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: shell hook injection failed: %v\n", err)
		} else {
			rcPath := daemon.ShellRCPath(shell)
			fmt.Printf("  Shell hook added to %s\n", rcPath)
		}
	}

	fmt.Println()
	fmt.Println("PDMCGuard installed successfully!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Open a new terminal (or run: source " + daemon.ShellRCPath(daemon.DetectShell()) + ")")
	fmt.Println("  2. Run: pdmcguard login")
	fmt.Println("  3. Navigate to a project — PDMCGuard will warn about critical advisories")
}

// verifyBinary sanity-checks the source file before a copy. Catches two
// real-world failure modes: 0-byte output from a silently failed `go build`
// and non-executable artifacts from partial transfers. Kept deliberately
// cheap (no subprocess) so it can never hang the install.
func verifyBinary(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("%s is 0 bytes", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not executable (mode %v)", path, info.Mode())
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
