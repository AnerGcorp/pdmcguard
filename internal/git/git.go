// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package git reads branch, remote, and commit directly from .git/ files.
// No os/exec — pure file I/O only.
package git

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrNoGitDir = errors.New("no .git directory found")
	ErrNoHead   = errors.New("cannot read HEAD")
)

const (
	maxWalkUp = 50
	cacheTTL  = 30 * time.Second
)

// Info holds git metadata for a project directory.
type Info struct {
	GitDir    string // absolute path to .git directory
	Branch    string // current branch name, or "" if detached
	CommitSHA string // 40-char hex SHA of HEAD
	RemoteURL string // origin remote URL, or "" if none
	Detached  bool   // true if HEAD is detached
}

// FindGitDir walks upward from startDir looking for a .git directory or file.
// If .git is a file (worktree/submodule), it follows the gitdir: pointer.
func FindGitDir(startDir string) (string, error) {
	dir := startDir
	for i := 0; i < maxWalkUp; i++ {
		gitPath := filepath.Join(dir, ".git")
		info, err := os.Lstat(gitPath)
		if err == nil {
			if info.IsDir() {
				return gitPath, nil
			}
			// .git is a file — worktree or submodule
			return followGitFile(gitPath, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", ErrNoGitDir
}

// followGitFile reads a .git file containing "gitdir: <path>" and resolves it.
func followGitFile(gitFile, parentDir string) (string, error) {
	data, err := os.ReadFile(gitFile)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(data))
	if !strings.HasPrefix(line, "gitdir: ") {
		return "", errors.New("invalid .git file: missing gitdir prefix")
	}
	target := strings.TrimPrefix(line, "gitdir: ")
	target = filepath.FromSlash(target)
	if !filepath.IsAbs(target) {
		target = filepath.Join(parentDir, target)
	}
	target = filepath.Clean(target)
	if _, err := os.Stat(target); err != nil {
		return "", err
	}
	return target, nil
}

// ReadInfo reads git metadata from the given .git directory.
func ReadInfo(gitDir string) (Info, error) {
	info := Info{GitDir: gitDir}

	ref, detached, err := readHEAD(gitDir)
	if err != nil {
		return info, err
	}
	info.Detached = detached

	if detached {
		info.CommitSHA = ref
	} else {
		// ref is like "refs/heads/main"
		info.Branch = strings.TrimPrefix(ref, "refs/heads/")
		sha, err := resolveRef(gitDir, ref)
		if err == nil {
			info.CommitSHA = sha
		}
	}

	url, _ := readRemoteURL(gitDir, "origin")
	info.RemoteURL = url

	return info, nil
}

// readHEAD parses .git/HEAD and returns the ref path or raw SHA.
func readHEAD(gitDir string) (ref string, detached bool, err error) {
	data, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return "", false, ErrNoHead
	}
	content := strings.TrimSpace(string(data))
	if strings.HasPrefix(content, "ref: ") {
		return strings.TrimPrefix(content, "ref: "), false, nil
	}
	// Detached HEAD — content is a raw SHA
	return content, true, nil
}

// resolveRef resolves a ref (e.g. "refs/heads/main") to a commit SHA.
// Tries loose ref first, then falls back to packed-refs.
func resolveRef(gitDir string, ref string) (string, error) {
	// If it already looks like a SHA, return it
	if len(ref) == 40 && isHex(ref) {
		return ref, nil
	}

	// Try loose ref file
	looseFile := filepath.Join(gitDir, filepath.FromSlash(ref))
	data, err := os.ReadFile(looseFile)
	if err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// Fall back to packed-refs
	return resolvePackedRef(gitDir, ref)
}

// resolvePackedRef searches .git/packed-refs for the given ref.
func resolvePackedRef(gitDir string, ref string) (string, error) {
	f, err := os.Open(filepath.Join(gitDir, "packed-refs"))
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' || line[0] == '^' {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 && parts[1] == ref {
			return parts[0], nil
		}
	}
	return "", errors.New("ref not found in packed-refs")
}

// readRemoteURL extracts the URL for the named remote from .git/config.
func readRemoteURL(gitDir string, remoteName string) (string, error) {
	f, err := os.Open(filepath.Join(gitDir, "config"))
	if err != nil {
		return "", err
	}
	defer f.Close()

	target := `[remote "` + remoteName + `"]`
	inSection := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == target {
			inSection = true
			continue
		}
		if inSection {
			if strings.HasPrefix(line, "[") {
				break // entered a new section
			}
			if strings.HasPrefix(line, "url") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1]), nil
				}
			}
		}
	}
	return "", nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Reader provides cached git metadata lookups.
type Reader struct {
	mu    sync.RWMutex
	cache map[string]cachedInfo
}

type cachedInfo struct {
	info Info
	at   time.Time
}

// NewReader creates a Reader with an empty cache.
func NewReader() *Reader {
	return &Reader{cache: make(map[string]cachedInfo)}
}

// Info returns git metadata for the project at the given directory.
// Results are cached for 30 seconds.
func (r *Reader) Info(projectDir string) (Info, error) {
	gitDir, err := FindGitDir(projectDir)
	if err != nil {
		return Info{}, err
	}

	r.mu.RLock()
	if cached, ok := r.cache[gitDir]; ok && time.Since(cached.at) < cacheTTL {
		r.mu.RUnlock()
		return cached.info, nil
	}
	r.mu.RUnlock()

	info, err := ReadInfo(gitDir)
	if err != nil {
		return info, err
	}

	r.mu.Lock()
	r.cache[gitDir] = cachedInfo{info: info, at: time.Now()}
	r.mu.Unlock()

	return info, nil
}
