<p align="center">
  <img src="assets/logo.png" alt="PDMCGuard" width="120" />
</p>

<h1 align="center">PDMCGuard</h1>

<p align="center">
  <strong>Passive Dependency Monitor & Compromise Guard</strong><br>
  Supply chain security for local development.
</p>

<p align="center">
  <a href="https://github.com/AnerGcorp/pdmcguard/releases"><img src="https://img.shields.io/github/v/release/AnerGcorp/pdmcguard?style=flat-square" alt="Release" /></a>
  <a href="https://github.com/AnerGcorp/pdmcguard/blob/main/LICENSE.md"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="License" /></a>
  <a href="https://pdmcguard.com"><img src="https://img.shields.io/badge/dashboard-pdmcguard.com-brightgreen?style=flat-square" alt="Dashboard" /></a>
</p>

> Watches your dependencies. Alerts you when a package is malicious.
> Even on projects you forgot you had.

---

## The problem

When a malicious package is discovered — a compromised version of a library
that steals API credentials, exfiltrates environment variables, or runs
arbitrary code on install — there is no automatic system that notifies
developers who installed it locally.

Package registries pull the version and post advisories. But they have no
contact channel to anonymous local users. If you ran `pip install` on your
laptop and never connected that project to a monitored repo or CI pipeline,
you simply never find out.

PDMCGuard fills this gap.

---

## How it works

Install a single binary, activate it once, forget about it.

```sh
curl -sSL https://pdmcguard.com/install.sh | sh
pdmcguard install    # register the service + inject the shell hook
pdmcguard start      # start the daemon
```

The daemon is registered as a launchd agent on macOS and a systemd user
service on Linux. Once started, it runs silently in the background, survives
reboots, and restarts itself on crash. It watches your project directories
using native OS APIs and intercepts package manager commands via a shell
hook — before they run.

When a dependency file changes, or when you run `npm install`, `pip install`,
or any recognised install command, PDMCGuard:

1. Reads your lock file and extracts every installed package + version
2. Checks against a local cache of critical advisories (offline, < 5ms)
3. Syncs to the cloud and runs full advisory matching across all severity levels
4. Alerts you immediately if any package is found to be malicious or compromised

Alerts reach you via desktop notification, email, and a web dashboard — even
for projects you cloned months ago and haven't touched since.

---

## Features

- **Pre-install blocking** — intercepts `npm install`, `pip install`, etc.
  before they run if a known-critical package is in your lock file
- **Git-aware detection** — catches malicious packages the moment `git clone`
  or `git pull` drops a lock file on disk, before you run anything
- **Retroactive matching** — when a new advisory is published, every historical
  snapshot is checked — not just current installs
- **Machine identity** — alerts tell you exactly which machine and project
  path the problem is on
- **Dormant project coverage** — critical alerts fire even on projects you
  stopped working on months ago
- **Offline resilient** — local critical cache works with no internet;
  cloud sync queues and flushes when connectivity returns
- **Zero configuration** — install once, never touch again

---

## Supported ecosystems

| Ecosystem | Files watched |
|-----------|--------------|
| Node.js | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json` |
| Python | `pyproject.toml`, `requirements.txt`, `Pipfile.lock`, `Pipfile` |
| Rust | `Cargo.lock`, `Cargo.toml` |
| Go | `go.sum`, `go.mod` |
| Ruby | `Gemfile.lock`, `Gemfile` |
| PHP | `composer.lock`, `composer.json` |

---

## Requirements

- macOS 12+ or Linux (kernel 4.x+)
- No root / sudo required
- No runtime dependencies — single static binary

Windows support is planned for a future release.

---

## Installation

**One-line install (recommended):**

```sh
curl -sSL https://pdmcguard.com/install.sh | sh
```

**Manual:**

Download the binary for your platform from
[GitHub Releases](https://github.com/AnerGcorp/pdmcguard/releases), verify the
checksum, and place it in your PATH. Then run:

```sh
pdmcguard install && pdmcguard start
```

`install` is configuration (copies the binary into `~/.pdmcguard/bin`, injects
the shell hook, registers the service). `start` is activation. Split into two
verbs because the original script already delivered the binary — running the
daemon is a deliberate second step.

---

## CLI reference

**Lifecycle:**

```sh
pdmcguard install               # copy binary, register service, inject shell hook
pdmcguard start                 # start the daemon (via service, or detached spawn)
pdmcguard stop                  # stop the daemon
pdmcguard uninstall             # remove service + shell hook (--purge also wipes data)
pdmcguard status                # service / daemon / sync / queue status at a glance
pdmcguard doctor                # deep health check across install, cache, IPC, config
pdmcguard version               # print version info
```

**Account + alerts:**

```sh
pdmcguard login                 # authenticate with the dashboard (offline mode also works)
pdmcguard ack <advisory-id>     # dismiss an advisory (--all-projects for global; --list to show)
pdmcguard unack <advisory-id>   # reverse a prior ack
pdmcguard pre-check             # run the pre-install check in the current directory
```

**Project scope:**

```sh
pdmcguard track [path]          # register a project with the running daemon (default: cwd)
pdmcguard untrack <path>        # alias for `exclude` — stop tracking a path
pdmcguard exclude <path>        # skip a path or basename from scans (--list to show rules)
pdmcguard unexclude <path>      # remove a previously-added exclusion rule
```

---

## How detection works

Two independent detection paths ensure no install event is missed:

- **Path A — shell hook:** fires synchronously before install commands
  (blocking if critical match found) and asynchronously after
- **Path B — file watcher:** OS-level watch on project directories; catches
  GUI-driven installs, `git clone`, and any tool that writes a lock file

The daemon operates with a local-first design — critical checks happen offline
in under 5ms. Full cloud matching runs asynchronously and covers all severity
levels with retroactive analysis.

---

## Privacy

PDMCGuard sends only what is necessary to match your dependencies against
known advisories:

- Package names and versions from your lock files
- Project path and machine hostname (for alert context)
- Git branch and remote URL (for alert context)

**PDMCGuard never reads or transmits:**

- Source code
- Environment variables or `.env` files
- Credentials or secrets
- File contents other than dependency lock files

The local daemon binary is fully open source and auditable. The cloud backend
is proprietary.

---

## Dashboard

Sign up at [pdmcguard.com](https://pdmcguard.com) to access the web dashboard.

The dashboard shows all machines, projects, snapshots, and alerts in one place.
It is the primary interface for reviewing alerts, understanding what was
exposed, and tracking remediation.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

PDMCGuard is licensed under AGPLv3. Contributions are welcome under the same
license.

---

## Security

To report a vulnerability in PDMCGuard itself, see [SECURITY.md](SECURITY.md).

---

## License

PDMCGuard is free and open source software licensed under the
[GNU Affero General Public License v3.0](LICENSE).

For commercial use cases that require a proprietary license, contact
[hello@pdmcguard.com](mailto:hello@pdmcguard.com).
