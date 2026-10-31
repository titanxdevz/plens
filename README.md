# PortLens (`plens`)

**PortLens** is a terminal-only server-exposure auditor for operators who run their own VPS/nodes. It doesn't just list open ports: it reveals what is exposed, whether it is actually dangerous, why, and gives you instant copy-paste remediation commands.

## Features
- **Two-phase fast scan**: High-concurrency async TCP discovery engine + targeted deep nmap inspection on open ports.
- **Inside vs. Outside correlation**: Map local listening processes (`/proc/net` or `ss` / `netstat`) against remote reachability (`EXPOSED`, `FILTERED`, `LOCAL_ONLY`, `GHOST`).
- **Safe verification probes**: Strictly read-only checks for unauthenticated Redis, MongoDB, Elasticsearch, Docker API, Memcached, FTP, and more.
- **Actionable fixes**: Ready-to-run copy-paste commands for `ufw`, `iptables`, `nftables`, and service configs.
- **Drift detection & baselines**: Track newly opened ports, closed ports, and changed services over time with alerts.
- **Per-host risk score (0-100)**: Deterministic severity-weighted scoring with historical trend tracking.

---

## Commands

### `plens scan <target...>`
Performs exposure audit across one or more target IPs or hostnames.
```bash
# Fast discovery scan
plens scan 192.168.1.100 --preset quick

# Standard scan with service identification
plens scan 192.168.1.100 --preset standard

# Comprehensive scan across all 65535 ports
plens scan 192.168.1.100 --preset full

# Web profile scan
plens scan example.com --profile web-server

# Inspect execution parameters and nmap commands without executing
plens scan 192.168.1.100 --preset standard --explain

# CI gate: fail if high or critical exposures are detected
plens scan 10.0.0.5 --fail-on high --yes --json

# Export to report formats (JSON, CSV, Markdown, standalone HTML)
plens scan 10.0.0.5 --html -o report.html
plens scan 10.0.0.5 --json -o scan.json
plens scan 10.0.0.5 --csv -o ports.csv
plens scan 10.0.0.5 --md -o report.md
```

### `plens self`
Audits local node listening sockets against external visibility, highlighting whether services are bound to `0.0.0.0` vs loopback and whether a firewall actually shields them. Shows process name, PID, external reachability, and verdict (`EXPOSED`, `FILTERED`, `LOCAL_ONLY`, `GHOST`).

### `plens fix <scan-id|finding-id>`
Generates grouped, deduplicated copy-paste remediation commands tailored for the detected environment (`ufw`, `iptables`, `nftables`, service configurations, and Docker port bindings).

### `plens baseline <set|show|clear> <target>`
Registers and manages expected port and service states for a target.
```bash
# Register latest scan as expected baseline
plens baseline set 10.0.0.5

# View registered baseline
plens baseline show 10.0.0.5
```

### `plens diff <a> <b>`
Compares two scans (or a scan against `latest` or `baseline`) with colored drift indicators (`+` new open ports, `-` closed ports, service changes, visibility changes, and risk score deltas).

### `plens history`
Displays historical scans with filters (`--target`, `--since`, `--has-findings`, `--limit`).

### `plens show <scan-id>`
Shows complete details of a past scan by scan ID.

### `plens ignore <rule|port> --reason "..." [--until YYYY-MM-DD]`
Temporarily or permanently suppresses specific findings with mandatory audit reasoning and optional expiration date.
```bash
plens ignore redis-noauth --target 10.0.0.5 --reason "Internal testing cluster" --until 2026-12-31
plens ignore --list
```
### `plens scan <target...> --profile <name>`
Evaluates server exposure against a declared profile of expected services.
- **Built-in profiles**:
  - `web-server`: Expects 80, 443; databases strictly local-only.
  - `database-server`: Restricts external connections; databases private/local-only.
  - `pterodactyl-panel`: Expects 80, 443; database local-only.
  - `pterodactyl-node`: Wings daemon API (8080), SFTP (2022), and game port ranges.
  - `minimal`: Hardened node (SSH on 22 only).

Any unallowed open port triggers an `unexpected-port` finding. Any expected port that is missing triggers a `missing-expected` advisory.

### `plens watch <target> [--every 5m]`
Continuously monitors a target on a repeating interval (e.g. `30s`, `5m`, `1h`), highlighting only detected drift in a rolling terminal view.

### `plens schedule <add|list|rm|run>`
Manages automated recurring background scans using standard cron syntax.
```bash
plens schedule add nightly-audit --target 10.0.0.5 --cron "0 2 * * *" --preset full
plens schedule list
```

### `plens daemon [--install-systemd]`
Runs the background scheduler loop. Supports `--install-systemd` to output/install a systemd service unit.

### `plens alert <test|config>`
Tests or inspects webhook integrations (Discord and generic JSON webhooks).

### `plens explain <port|service>`
Provides plain-language offline guidance explaining the service, risk factors, and recommended hardening.

### `plens doctor`
Validates environment prerequisites: nmap presence, permissions, socket descriptor limits, SQLite database, and webhook connectivity.

### `plens completions <shell>`
Generates shell autocompletion scripts for bash, zsh, fish, powershell, or elvish.
