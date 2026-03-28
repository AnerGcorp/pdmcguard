# Contributing to PDMCGuard

Thank you for taking the time to contribute. PDMCGuard is a security tool used
by developers who trust it to protect their machines — contributions are held to
a high standard of correctness and care.

---

## Before you start

- Check the [open issues](https://github.com/pdmcguard/agent/issues) to see if
  your idea or bug is already being tracked
- For significant changes, open an issue first to discuss the approach before
  writing code — this avoids duplicate effort
- All contributions must be licensed under AGPLv3 (see [LICENSE](LICENSE))

---

## What we welcome

- Bug fixes with a clear reproduction case
- New PDMC file type support (new ecosystems)
- Improvements to the shell hook (new shells, edge cases)
- New directory classifier fingerprints (new venv / build output patterns)
- Performance improvements to the matching engine or local cache
- Documentation fixes and clarifications
- Test coverage improvements

## What we are cautious about

- Changes to the advisory feed ingestion pipeline — incorrect advisory data
  causes false positives that erode user trust, which is the product's core asset
- Changes to the pre-install blocking logic — a bug here either silently fails
  to protect users or blocks legitimate installs
- New external runtime dependencies in the daemon binary — it must remain a
  single static binary with no required system libraries

---

## Development setup

### Prerequisites

- Go 1.22 or later
- Python 3.10+ (for the advisory worker scripts)
- `make`
- A Supabase project (free tier is fine) for integration tests

### Clone and build

```sh
git clone https://github.com/pdmcguard/agent.git
cd agent
make deps      # download Go module dependencies
make build     # build binary for your current platform
make test      # run unit tests
```

### Cross-compile

```sh
make build-all   # builds for darwin/amd64, darwin/arm64, linux/amd64, linux/arm64
```

Binaries land in `./dist/`.

### Run locally (without installing as a service)

```sh
./dist/pdmcguard-darwin-arm64 status     # check if a daemon is already running
./dist/pdmcguard-darwin-arm64 pre-check  # run a pre-install check in cwd
```

To run the full daemon in foreground mode for development:

```sh
PDMCGUARD_DEV=1 ./dist/pdmcguard-darwin-arm64 daemon --foreground
```

`PDMCGUARD_DEV=1` disables service registration and writes logs to stdout.

---

## Project structure

```
cmd/pdmcguard/        main binary entry point
internal/
  cache/              local critical advisory cache (SQLite)
  classifier/         venv / node_modules / .git fingerprint detection
  daemon/             OS service registration (launchd, systemd)
  git/                direct .git file readers (no git binary)
  hook/               shell hook snippet generation and injection
  notify/             SSE listener + OS desktop notifications
  sync/               cloud sync queue (SQLite) and syncer goroutine
  watcher/            fsnotify wrapper + PDMC filename filter
workers/              Python advisory feed workers (run server-side)
scripts/              bootstrap and seed scripts
```

---

## Code style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Run `make lint` before submitting — this runs `golangci-lint`
- No external dependencies added to the daemon without discussion
- Every exported function needs a doc comment
- Error handling: always wrap errors with context using `fmt.Errorf("...: %w", err)`
- No `panic()` in library code — only in `main()` for truly unrecoverable states

---

## Testing

### Unit tests

```sh
make test
```

Tests live alongside the code they test (`foo_test.go` next to `foo.go`).

For the classifier and pre-check logic, use fixture directories under
`testdata/` — do not rely on the real filesystem in tests.

### Integration tests

Integration tests require a Supabase project. Copy `.env.test.example` to
`.env.test` and fill in your credentials:

```sh
cp .env.test.example .env.test
# edit .env.test with your test Supabase URL and anon key
make test-integration
```

Integration tests are not run in CI for external contributors — a maintainer
will run them before merging.

### Pre-install check tests

The pre-install check is security-critical. Any change to
`internal/cache/` or the hook intercept logic must include:

1. A test that verifies a known-critical package is blocked
2. A test that verifies a clean package adds < 10ms latency
3. A test that verifies the check degrades gracefully when the cache is empty

---

## Submitting a pull request

1. Fork the repository and create a branch from `main`:
   ```sh
   git checkout -b fix/classifier-inode-rename
   ```

2. Make your changes. Keep commits small and focused — one logical change per
   commit with a clear message:
   ```
   classifier: key venv exclusion by inode instead of path

   Renames no longer cause the daemon to re-scan a previously excluded
   directory. Exclusion entries now store the inode number from stat(2)
   rather than the absolute path string.

   Fixes #42
   ```

3. Ensure tests pass and linter is clean:
   ```sh
   make test
   make lint
   ```

4. Open a pull request against `main`. The PR description should include:
   - What the change does and why
   - How to test it manually if relevant
   - Any security implications (even if none)

5. A maintainer will review within a few days. Security-sensitive changes
   (pre-install check, advisory matching, sync endpoint) require two reviewers.

---

## Reporting bugs

Open a [GitHub issue](https://github.com/pdmcguard/agent/issues/new) with:

- PDMCGuard version (`pdmcguard status` shows this)
- OS and version
- What you expected to happen
- What actually happened
- Steps to reproduce

For crashes, include the output of:
```sh
PDMCGUARD_DEV=1 pdmcguard daemon --foreground 2>&1
```

---

## Reporting security vulnerabilities

**Do not open a public issue for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## Commit message format

```
<scope>: <short summary in present tense, lowercase>

<optional body — explain the why, not the what>

<optional footer — Fixes #N, Closes #N>
```

Scopes: `daemon`, `watcher`, `hook`, `classifier`, `cache`, `sync`,
`notify`, `git`, `worker`, `docs`, `ci`, `build`

---

## License

By contributing to PDMCGuard, you agree that your contributions will be
licensed under the GNU Affero General Public License v3.0.