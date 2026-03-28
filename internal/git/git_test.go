// PDMCGuard — Passive Dependency Monitor & Critical Guard
// Copyright (C) 2026 AnerGcorp
// SPDX-License-Identifier: AGPL-3.0-or-later

package git

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testSHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

// makeGitDir creates a minimal .git directory with HEAD, ref, and config.
func makeGitDir(t *testing.T, dir string, branch string, sha string, remoteURL string) string {
	t.Helper()
	gitDir := filepath.Join(dir, ".git")
	os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o755)
	os.MkdirAll(filepath.Join(gitDir, "objects"), 0o755)

	// HEAD
	os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/"+branch+"\n"), 0o644)

	// Loose ref
	os.WriteFile(filepath.Join(gitDir, "refs", "heads", branch), []byte(sha+"\n"), 0o644)

	// Config
	config := "[core]\n\trepositoryformatversion = 0\n"
	if remoteURL != "" {
		config += "[remote \"origin\"]\n\turl = " + remoteURL + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	}
	os.WriteFile(filepath.Join(gitDir, "config"), []byte(config), 0o644)

	return gitDir
}

func TestFindGitDir_Direct(t *testing.T) {
	root := t.TempDir()
	expected := makeGitDir(t, root, "main", testSHA, "")

	gitDir, err := FindGitDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if gitDir != expected {
		t.Errorf("expected %s, got %s", expected, gitDir)
	}
}

func TestFindGitDir_WalksUp(t *testing.T) {
	root := t.TempDir()
	expected := makeGitDir(t, root, "main", testSHA, "")

	sub := filepath.Join(root, "src", "pkg")
	os.MkdirAll(sub, 0o755)

	gitDir, err := FindGitDir(sub)
	if err != nil {
		t.Fatal(err)
	}
	if gitDir != expected {
		t.Errorf("expected %s, got %s", expected, gitDir)
	}
}

func TestFindGitDir_NotFound(t *testing.T) {
	root := t.TempDir()
	_, err := FindGitDir(root)
	if !errors.Is(err, ErrNoGitDir) {
		t.Errorf("expected ErrNoGitDir, got %v", err)
	}
}

func TestFindGitDir_WorktreeFile(t *testing.T) {
	root := t.TempDir()

	// Create the real git dir elsewhere
	realGitDir := filepath.Join(root, "real-repo.git", "worktrees", "wt1")
	os.MkdirAll(realGitDir, 0o755)
	os.WriteFile(filepath.Join(realGitDir, "HEAD"), []byte("ref: refs/heads/feature\n"), 0o644)

	// Create a worktree directory with .git as a file
	worktree := filepath.Join(root, "worktree")
	os.MkdirAll(worktree, 0o755)
	os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+realGitDir+"\n"), 0o644)

	gitDir, err := FindGitDir(worktree)
	if err != nil {
		t.Fatal(err)
	}
	if gitDir != realGitDir {
		t.Errorf("expected %s, got %s", realGitDir, gitDir)
	}
}

func TestReadHEAD_Branch(t *testing.T) {
	root := t.TempDir()
	gitDir := makeGitDir(t, root, "develop", testSHA, "")

	ref, detached, err := readHEAD(gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if detached {
		t.Error("expected not detached")
	}
	if ref != "refs/heads/develop" {
		t.Errorf("expected refs/heads/develop, got %s", ref)
	}
}

func TestReadHEAD_Detached(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	os.MkdirAll(gitDir, 0o755)
	os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(testSHA+"\n"), 0o644)

	ref, detached, err := readHEAD(gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if !detached {
		t.Error("expected detached")
	}
	if ref != testSHA {
		t.Errorf("expected %s, got %s", testSHA, ref)
	}
}

func TestResolveRef_Loose(t *testing.T) {
	root := t.TempDir()
	gitDir := makeGitDir(t, root, "main", testSHA, "")

	sha, err := resolveRef(gitDir, "refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if sha != testSHA {
		t.Errorf("expected %s, got %s", testSHA, sha)
	}
}

func TestResolveRef_Packed(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	os.MkdirAll(gitDir, 0o755)

	// No loose ref — only packed-refs
	packedContent := "# pack-refs with: peeled fully-peeled sorted\n" +
		testSHA + " refs/heads/feature\n" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb refs/heads/main\n"
	os.WriteFile(filepath.Join(gitDir, "packed-refs"), []byte(packedContent), 0o644)

	sha, err := resolveRef(gitDir, "refs/heads/feature")
	if err != nil {
		t.Fatal(err)
	}
	if sha != testSHA {
		t.Errorf("expected %s, got %s", testSHA, sha)
	}
}

func TestResolveRef_PackedWithComments(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	os.MkdirAll(gitDir, 0o755)

	packedContent := "# pack-refs with: peeled fully-peeled sorted\n" +
		"cccccccccccccccccccccccccccccccccccccccc refs/tags/v1.0\n" +
		"^dddddddddddddddddddddddddddddddddddddddd\n" + // peel line
		testSHA + " refs/heads/release\n"
	os.WriteFile(filepath.Join(gitDir, "packed-refs"), []byte(packedContent), 0o644)

	sha, err := resolveRef(gitDir, "refs/heads/release")
	if err != nil {
		t.Fatal(err)
	}
	if sha != testSHA {
		t.Errorf("expected %s, got %s", testSHA, sha)
	}
}

func TestReadRemoteURL_Found(t *testing.T) {
	root := t.TempDir()
	gitDir := makeGitDir(t, root, "main", testSHA, "git@github.com:AnerGcorp/pdmcguard.git")

	url, err := readRemoteURL(gitDir, "origin")
	if err != nil {
		t.Fatal(err)
	}
	if url != "git@github.com:AnerGcorp/pdmcguard.git" {
		t.Errorf("got %q", url)
	}
}

func TestReadRemoteURL_NotFound(t *testing.T) {
	root := t.TempDir()
	gitDir := makeGitDir(t, root, "main", testSHA, "") // no remote

	url, err := readRemoteURL(gitDir, "origin")
	if err != nil {
		t.Fatal(err)
	}
	if url != "" {
		t.Errorf("expected empty URL, got %q", url)
	}
}

func TestReadRemoteURL_MultipleRemotes(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	os.MkdirAll(gitDir, 0o755)

	config := `[core]
	repositoryformatversion = 0
[remote "upstream"]
	url = https://github.com/upstream/repo.git
	fetch = +refs/heads/*:refs/remotes/upstream/*
[remote "origin"]
	url = git@github.com:me/fork.git
	fetch = +refs/heads/*:refs/remotes/origin/*
`
	os.WriteFile(filepath.Join(gitDir, "config"), []byte(config), 0o644)

	url, err := readRemoteURL(gitDir, "origin")
	if err != nil {
		t.Fatal(err)
	}
	if url != "git@github.com:me/fork.git" {
		t.Errorf("expected fork URL, got %q", url)
	}
}

func TestReadInfo_Integration(t *testing.T) {
	root := t.TempDir()
	makeGitDir(t, root, "feature-x", testSHA, "https://github.com/test/repo.git")

	gitDir := filepath.Join(root, ".git")
	info, err := ReadInfo(gitDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Branch != "feature-x" {
		t.Errorf("branch: got %q, want feature-x", info.Branch)
	}
	if info.CommitSHA != testSHA {
		t.Errorf("sha: got %q, want %s", info.CommitSHA, testSHA)
	}
	if info.RemoteURL != "https://github.com/test/repo.git" {
		t.Errorf("remote: got %q", info.RemoteURL)
	}
	if info.Detached {
		t.Error("expected not detached")
	}
}

func TestReader_Cache(t *testing.T) {
	root := t.TempDir()
	makeGitDir(t, root, "main", testSHA, "")
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module test"), 0o644)

	reader := NewReader()

	// First call — populates cache
	info1, err := reader.Info(root)
	if err != nil {
		t.Fatal(err)
	}
	if info1.Branch != "main" {
		t.Errorf("expected main, got %s", info1.Branch)
	}

	// Change the branch on disk
	os.WriteFile(filepath.Join(root, ".git", "HEAD"), []byte("ref: refs/heads/changed\n"), 0o644)

	// Second call within TTL — should return cached (still "main")
	info2, err := reader.Info(root)
	if err != nil {
		t.Fatal(err)
	}
	if info2.Branch != "main" {
		t.Errorf("expected cached 'main', got %s (cache was not used)", info2.Branch)
	}

	// Manually expire the cache
	reader.mu.Lock()
	for k, v := range reader.cache {
		v.at = time.Now().Add(-2 * cacheTTL)
		reader.cache[k] = v
	}
	reader.mu.Unlock()

	// Third call — cache expired, should read fresh data
	info3, err := reader.Info(root)
	if err != nil {
		t.Fatal(err)
	}
	if info3.Branch != "changed" {
		t.Errorf("expected fresh 'changed', got %s", info3.Branch)
	}
}
