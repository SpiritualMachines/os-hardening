# FreeBSD — Provisioning & Hardening Instructions

## Overview

These scripts apply a practical security baseline to FreeBSD 13 or 14. The workflow is split into two stages:

1. **`provision.sh`** — Bootstraps `pkg`, installs security tools, runs a vulnerability audit, and enables the BSM audit daemon. Run once on a fresh installation.
2. **`harden.sh`** — Applies all hardening. Safe to re-run at any time (idempotent).

---

## Prerequisites

- FreeBSD 13.x or 14.x
- Root access
- Internet access for `provision.sh`
- An SSH key installed before running `harden.sh` — the SSH section disables password authentication if a key is found

---

## Scripts

### `provision.sh` — Package bootstrap and security tooling

Run first. Bootstraps and updates `pkg`, installs required security packages, audits currently-installed packages for known CVEs, and enables the BSM audit daemon.

```
Usage: sudo bash provision.sh [--dry-run]
```

**What it does:**

| Step | Details |
|---|---|
| Bootstrap pkg | Runs `pkg bootstrap` and `pkg update` |
| Install packages | `sudo`, `bash`, `py311-fail2ban` (or available version), `py311-pip`, audit tools as available |
| pkg audit | Runs `pkg audit -F` to check all installed packages against the VuXML vulnerability database |
| Enable audit daemon | Sets `auditd_enable="YES"` in `/etc/rc.conf`, starts `auditd` |

---

### `harden.sh` — System hardening

Run after `provision.sh`. Auto-detects the primary network interface and SSH port.

```
Usage: sudo bash harden.sh [OPTIONS]

Options:
  --ssh-port PORT    SSH port to open in pf (default: auto-detected from sshd or 22)
  --skip SECTIONS    Comma-separated list of sections to skip
                     Values: pf, rc, sysctl, ssh, coredumps, periodic
  --dry-run          Show what would be done without making changes
  --help             Show this help
```

**Sections applied:**

| # | Section | What it does |
|---|---|---|
| 1 | `pf` | Deploys a hardened `/etc/pf.conf`. Default-deny inbound, allow established outbound, ICMP from local subnet, SSH from any. Enables `pf` and `pflog` in `rc.conf`. Validates ruleset with `pfctl -nf` before loading. Backs up existing `pf.conf`. |
| 2 | `rc` | Hardens `/etc/rc.conf`: disables sendmail (all four components), rpcbind, inetd. Adds `-ss -c` flags to syslogd (no remote syslog, no DNS lookups). Disables kernel crash dumps (`dumpdev="NO"`). |
| 3 | `sysctl` | Appends network and kernel hardening block to `/etc/sysctl.conf` (see details below). Applied immediately. |
| 4 | `ssh` | Writes hardened `/etc/ssh/sshd_config`. Disables password auth if SSH keys are present, disables root login, sets strong algorithms, `MaxAuthTries 3`. Backs up existing config. Validates with `sshd -t` before restarting. |
| 5 | `coredumps` | Sets `coredumpsize=0` in `/etc/login.conf` default class (via `cap_mkdb`). Belt-and-suspenders with `kern.coredump=0` in sysctl. |
| 6 | `periodic` | Appends security configuration to `/etc/periodic.conf`: daily `pkg audit`, setuid binary change detection, passwd/group change monitoring, package change reporting. |

---

## pf Firewall

The deployed ruleset structure:

```
# Default policies
block in  log all          # Block and log all inbound (logged to pflog0)
block out all              # Block all outbound

# Loopback
pass quick on lo0 all      # Allow all loopback

# Outbound
pass out on $ext_if all keep state    # Allow all outbound; keep state for return traffic

# ICMP from local subnet only
pass in on $ext_if proto icmp from $local_net icmp-type echoreq keep state

# SSH (restrict to local_net if desired)
pass in on $ext_if proto tcp from any to any port $ssh_port keep state
```

**To open additional services:**
```
pass in on $ext_if proto tcp from $local_net to any port 443 keep state
```

**Verification:**
```bash
pfctl -sr          # show ruleset
pfctl -si          # show counters and state
pfctl -nf /etc/pf.conf   # validate without loading
tcpdump -n -e -ttt -i pflog0   # watch blocked packets
```

---

## rc.conf Services Disabled

| Service | Why |
|---|---|
| `sendmail` | All four components. Opens ports 25/587. Disable unless this machine sends/receives mail directly. |
| `rpcbind` | NFS portmapper (port 111). Disable if NFS is not needed. |
| `inetd` | Legacy super-server. Almost never needed on modern FreeBSD. |
| `syslogd` `-ss -c` flags | Prevents listening for remote syslog on UDP 514; disables DNS lookups for logged IPs. |

> If you need NFS: pass `--skip rc` or manually re-enable `rpcbind` after running the script.

---

## sysctl Settings Applied

Appended to `/etc/sysctl.conf` within `### BEGIN secure_oss SYSCTL ###` / `### END secure_oss SYSCTL ###` markers for idempotency.

**Network hardening:**

| Parameter | Value | Purpose |
|---|---|---|
| `net.inet.tcp.drop_synfin` | `1` | Drop TCP SYN+FIN (invalid, used in scans) |
| `net.inet.tcp.blackhole` | `2` | Silently drop TCP to closed ports (no RST — hides closed ports from scanners) |
| `net.inet.udp.blackhole` | `1` | Silently drop UDP to closed ports |
| `net.inet.ip.random_id` | `1` | Randomize IP ID (prevents OS fingerprinting) |
| `net.inet.icmp.drop_redirect` | `1` | Drop ICMP redirects (MITM prevention) |
| `net.inet.ip.redirect` | `0` | Don't send IP redirects (not a router) |
| `net.inet.ip.sourceroute` | `0` | Block source-routed packets |
| `net.inet.tcp.syncookies` | `1` | SYN flood protection |

**Security hardening:**

| Parameter | Value | Purpose |
|---|---|---|
| `security.bsd.see_other_uids` | `0` | Users cannot see processes owned by other users |
| `security.bsd.see_other_gids` | `0` | Users cannot see processes of other groups |
| `security.bsd.unprivileged_read_msgbuf` | `0` | Unprivileged users cannot read dmesg (hides kernel addresses) |
| `security.bsd.unprivileged_proc_debug` | `0` | Restricts ptrace to parent processes (no lateral process inspection) |
| `security.bsd.hardlink_check_uid` | `1` | Prevent hardlinks to files the user doesn't own (TOCTOU prevention) |
| `security.bsd.hardlink_check_gid` | `1` | Same check for group ownership |
| `kern.coredump` | `0` | Disable kernel crash dumps |
| `kern.randompid` | `337` | Randomize PID allocation (makes PID-prediction attacks harder) |

---

## Periodic Security (daily/weekly)

Appended to `/etc/periodic.conf`:

| Check | Schedule | What it does |
|---|---|---|
| `daily_pkgaudit_enable` | Daily | Runs `pkg audit` and reports newly disclosed CVEs for installed packages |
| `daily_status_security_inline` | Daily | Reports changes to setuid/setgid binaries |
| `daily_status_security_passwd` | Daily | Reports changes to `/etc/passwd` and `/etc/group` |
| `weekly_status_pkg_changes_enable` | Weekly | Reports installed package changes |

Output is mailed to `root`. To forward to an external address:
```bash
echo "root: your@email.com" >> /etc/aliases && newaliases
```

---

## Idempotency

Applied sections are tracked in `/etc/secure_oss/applied/`. Re-running skips already-applied sections.

To force re-application of a section:
```bash
rm /etc/secure_oss/applied/pf
sudo bash harden.sh --skip rc,sysctl,ssh,coredumps,periodic
```

All output is logged to `/var/log/secure_oss.log`.

---

## Full Workflow

```bash
# Step 1 — provision packages
sudo bash provision.sh

# Step 2 — apply hardening (auto-detects interface and SSH port)
sudo bash harden.sh

# Step 2a — specify a non-standard SSH port:
sudo bash harden.sh --ssh-port 2222

# Step 3 — verify
pfctl -sr
sysctl security.bsd.see_other_uids net.inet.tcp.blackhole
sshd -T | grep -E 'permitrootlogin|passwordauth|maxauthtries'
sysctl kern.coredump    # should be 0
```

---

## Post-Hardening Checklist

```
[ ] Verify SSH access works before ending your current session
[ ] Open additional pf ports for any services this host runs
[ ] Forward root mail to an external address for security alerts:
      echo "root: your@email.com" >> /etc/aliases && newaliases
[ ] Review /etc/periodic.conf for any additional checks to enable
[ ] Run pkg audit manually to confirm no current vulnerabilities:
      pkg audit -F
[ ] Consider enabling mtree for filesystem change tracking:
      /usr/sbin/mtree -cU -p / > /etc/mtree/secure_oss.spec
      # Then set daily_mtree_enable="YES" in /etc/periodic.conf
```

---

## FreeBSD-Specific Notes

- `rc.conf` is the primary service configuration file — enable/disable services via `service_name_enable="YES"/"NO"`
- `pf` is loaded at boot if `pf_enable="YES"` is set in `rc.conf`
- `pflog0` is a virtual interface that captures logged packets — inspect with `tcpdump -i pflog0`
- `/etc/login.conf` controls resource limits per login class; run `cap_mkdb /etc/login.conf` after changes
- `sshd -t` validates `/etc/ssh/sshd_config` syntax without restarting the daemon
