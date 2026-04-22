# Changelog

All notable changes to the PDMCGuard agent are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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