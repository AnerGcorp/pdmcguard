# Security Policy

PDMCGuard is a security tool. Vulnerabilities in PDMCGuard itself — the daemon,
the shell hook, the advisory matching engine, or the cloud backend — could
directly harm the developers who trust it to protect them. We take reports
seriously and respond quickly.

---

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older | No |

Always run the latest version. `pdmcguard status` shows your current version.
The daemon checks for updates on startup and prints a notice if a newer version
is available.

---

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately by emailing:

**security@pdmcguard.com**

Include as much of the following as you can:

- Description of the vulnerability and its potential impact
- Steps to reproduce, or a minimal proof of concept
- PDMCGuard version affected (`pdmcguard status`)
- Your OS and version
- Whether you believe it is being actively exploited

We will acknowledge your report within **48 hours** and aim to provide an
initial assessment within **5 business days**.

If you do not receive a response within 48 hours, follow up at the same address
with `[SECURITY FOLLOW-UP]` in the subject line.

---

## Disclosure policy

We follow coordinated disclosure:

1. You report privately to security@pdmcguard.com
2. We confirm receipt within 48 hours
3. We investigate and develop a fix
4. We agree on a disclosure date — typically 90 days from report, sooner if
   a fix is ready
5. We release the fix and publish a security advisory
6. You are credited in the advisory (unless you prefer to remain anonymous)

We will not take legal action against researchers who report vulnerabilities
in good faith and follow this process.

---

## Scope

### In scope

- **Local daemon** (`pdmcguard` binary) — privilege escalation, arbitrary code
  execution, data exfiltration beyond what is documented, bypass of the
  pre-install blocking check
- **Shell hook** — injection of arbitrary commands, bypass of the pre-install
  intercept, unintended execution of blocked packages
- **Local SQLite databases** — unauthorised read or write of
  `~/.pdmcguard/critical.db`, `queue.db`, or `excludes.db` by other processes
- **Cloud sync endpoint** — authentication bypass, ability to poison another
  user's advisory data or snapshots, data leakage between user accounts
- **Advisory matching engine** — logic flaws that cause known-malicious
  packages to be marked clean, or clean packages to be permanently blocked
- **Dashboard** — authentication bypass, cross-account data access, XSS that
  could expose API tokens

### Out of scope

- Vulnerabilities in upstream advisory feeds (OSV, OSSF, GHSA) — report those
  to their respective maintainers
- Denial of service via resource exhaustion on a single machine
- Issues requiring physical access to the target machine
- Social engineering attacks
- Findings from automated scanners without a demonstrated exploit
- Vulnerabilities in third-party dependencies where no exploit path in
  PDMCGuard exists

---

## High-severity scenarios we are particularly concerned about

**Pre-install block bypass:** Any method that allows a known-critical package
to be installed without triggering the blocking warning. This is the primary
protection for vibe coders who do not read lock files manually.

**Advisory poisoning:** Any method that allows a malicious actor to insert
false advisories into a user's local cache or cloud advisory table, either
to block legitimate packages or to suppress real alerts.

**Daemon privilege escalation:** The daemon runs as the current user without
elevated privileges. Any path to root or to another user's data is critical.

**Shell hook command injection:** The hook intercepts shell commands. Any
path from a crafted package name or project path to unintended shell execution
is critical.

---

## Security design notes

These are documented here so researchers understand what is intentional:

- The daemon runs entirely as the current user. It does not require or request
  elevated privileges at any point, including during `pdmcguard install`.
- The local critical cache (`critical.db`) is readable by the current user
  only (`chmod 600`). It contains only package names, versions, and advisory
  IDs — no user credentials or private data.
- The cloud sync payload contains only package names, versions, project paths,
  and machine hostname. Source code, environment variables, and file contents
  are never read or transmitted.
- The `--no-pdmcguard` override flag on install commands is intentional. A
  security tool that permanently blocks a developer's workflow will be
  uninstalled. The override is logged locally but does not suppress the
  desktop notification or cloud alert.
- The shell hook uses `preexec` and `DEBUG` trap mechanisms. It does not wrap
  or proxy the install command — it either exits 0 (command runs normally) or
  exits non-zero (command is blocked). There is no man-in-the-middle of the
  install process.

---

## Bug bounty

PDMCGuard does not currently operate a paid bug bounty programme. We offer
public credit in the security advisory and a personal thank-you for reports
that lead to a fix.

---

## Hall of fame

Researchers who have responsibly disclosed vulnerabilities will be listed here
with their permission.

*(none yet — be the first)*