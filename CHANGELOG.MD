# Changelog

All notable changes to the PDMCGuard agent are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `pdmcguard doctor` one-shot health check. Runs eleven read-only checks
  across install state (config dir, installed binary, PATH resolution,
  system service, shell hook block integrity), auth (credentials file),
  cache (reachability + SQLite `PRAGMA integrity_check`), sync (queue
  depth), consistency (`alerts.flag` vs `HasAnyCritical`), and the
  user excludes file. Emits `[OK]` / `[WARN]` / `[FAIL]` rows with a
  summary line; exit code 1 iff any check fails (WARN is advisory and
  does not fail the command, so `pdmcguard doctor && ...` survives
  offline mode). `--verbose` expands skipped-excludes line numbers,
  sentinel drift context, and other diagnostics.
- `daemon.InspectHook(shell)` and `excludes.Inspect(path)` — structured
  readback helpers backing doctor. `InspectHook` shares the
  `hookStartMarker` / `hookEndMarker` constants with `InjectHook` so
  detection stays in sync with injection; `excludes.Inspect` reports
  parsed-vs-skipped line counts where `Load` would have silently dropped
  bad lines.
- `cache.Store.IntegrityCheck()` wraps SQLite's `PRAGMA integrity_check`
  so doctor doesn't reach around cache's private `*sql.DB`.
- Path-based user exclusion mechanism. `pdmcguard exclude <path>` adds a
  prefix rule; `pdmcguard exclude <basename>` adds a component-match
  rule (e.g. `node_modules` silences every `node_modules` tree anywhere).
  Rules persist to `~/.pdmcguard/excludes` and are enforced at both
  bootstrap scan time and the live watcher — so a rule added to a running
  daemon takes effect within one stat (via mtime-based hot reload) instead
  of waiting for a restart.
- `pdmcguard exclude --list` shows active user rules and the hardcoded
  `[default]` list (`node_modules`, `.yarn`, `target`, `dist`, `build`,
  `.next`, `.venv`, `venv`, `.tox`, `.cache`, `.gradle`, `vendor`, …).
- `pdmcguard unexclude <path>` reverses a prior exclude. The daemon
  re-populates alerts on its next scan.
- `pdmcguard exclude` performs a one-shot DB cleanup: `project_alerts`
  and per-project `project_acks` rows under the newly-excluded subtree
  are wiped immediately, then the alert sentinel is reconciled so a
  fully-silenced machine goes quiet without a second round-trip. Global
  acks (`project_dir = '*'`) are preserved.

### Changed
- `bootstrap.Scan` and `watcher.New` both accept a `*excludes.Matcher`
  argument. Call sites in tests that pass `nil` continue to work —
  matcher is optional, defaults still apply for the CLI path.

---

## [0.3.1] - 2026-04-22

### Fixed
- `pdmcguard install` now adds `~/.pdmcguard/bin` to `PATH` inside the
  shell-hook block it owns, so `pdmcguard <subcommand>` resolves to the
  freshly-installed binary instead of a stale global copy (or
  "command not found" on clean machines). Existing installs pick up
  the fix by re-running `pdmcguard install` — `InjectHook` now strips
  any prior block and rewrites, making the installer a real upgrade
  vector instead of short-circuiting on "already present".
- Shell-hook PATH line uses shell-specific syntax: `export PATH=...`
  for bash/zsh, `set -gx PATH ...` for fish.

---

## [0.3.0] - 2026-04-22

### Added
- `pdmcguard ack <advisory-id>` permanently dismisses an advisory in the
  current project. `--all-projects` scopes the ack globally. `unack`
  reverses it; `ack --list` shows every recorded ack. Ack state lives on
  its own `project_acks` table so it survives every daemon re-sync.
- Startup baseline scan classifies every tracked project once before
  entering the event loop, so the shell-hook pre-check is accurate on
  the very first `cd` after daemon start. Opt-out via `--no-baseline`
  or `PDMCGUARD_BASELINE=0`.
- Background reconnect-and-drain loop in the sync engine picks up a
  mid-session `pdmcguard login` within ~60s and retries the API after
  transient failures, so offline-queued work no longer waits for a
  process restart.

### Changed
- `CriticalAlerts` and `HasAnyCritical` now filter out acked advisories
  at the query layer, including the zero-cost `alerts.flag` sentinel
  path — a fully-acked machine goes silent without forking the binary.
- `updateAlertSentinel` promoted to package-level
  `sync.ReconcileAlertSentinel(*cache.Store)` so one-shot mutations
  (e.g. the ack CLI) can tick the sentinel without standing up a full
  Engine.

### Fixed
- Shell-hook banner no longer re-prints on every prompt: a 24h quiet
  window gated by `last_shown_at` suppresses the same banner until the
  window elapses.
- Startup sentinel reconcile: on first start after install, the
  baseline scan now writes/removes `~/.pdmcguard/alerts.flag` to match
  actual DB state, fixing a case where the shell hook wouldn't fire on
  the first `cd` even with critical alerts present.
- Project directory canonicalization at cache ingress resolves
  symlinks and trims trailing slashes, stopping the same logical
  project from accumulating duplicate alert rows under divergent keys.
- `pdmcguard uninstall` (without `--purge`) now removes the installed
  binary — previously a stale binary could linger on PATH after the
  service was removed.
- `pdmcguard install` refuses to publish the in-tree source binary and
  requires a `make build` first, preventing a corrupt
  `go run`-style artifact from being copied into the system location.

---

## [0.2.0] - prior release

### Added
- Initial release of the PDMCGuard local agent

---

<!-- New releases are added above this line in the format below:

## [0.2.0] - YYYY-MM-DD

### Added
- Description of new feature

### Changed
- Description of changed behaviour

### Fixed
- Description of bug fix

### Removed
- Description of removed feature

-->