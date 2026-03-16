# Ubuntu Server — Provisioning & Hardening Instructions

## Overview

These scripts apply a practical security baseline to Ubuntu Server 22.04 LTS or 24.04 LTS. The workflow is split into two stages:

1. **`provision.sh`** — Installs required security packages and removes Ubuntu telemetry. Run once on a fresh installation.
2. **`harden.sh`** — Applies all hardening. Safe to re-run at any time (idempotent).

---

## Prerequisites

- Ubuntu Server 22.04 LTS or 24.04 LTS
- Root / sudo access
- Internet access (for `provision.sh`)
- An SSH key installed in `authorized_keys` before running `harden.sh` — the SSH section will disable password authentication if a key is found

---

## Scripts

### `provision.sh` — Package installation and telemetry removal

Run first. Updates apt, installs security tools, and removes Ubuntu telemetry packages.

```
Usage: sudo bash provision.sh [OPTIONS]

Options:
  --keep-snap         Do not remove snapd (keep if you depend on snap packages)
  --keep-ubuntu-pro   Do not remove ubuntu-advantage-tools / ubuntu-pro-client
  --dry-run           Show what would be done without making changes
  --help              Show this help
```

**What it does:**

| Step | Details |
|---|---|
| apt update | Refreshes package lists |
| Install packages | `ufw`, `fail2ban`, `auditd`, `audispd-plugins`, `libpam-pwquality`, `unattended-upgrades`, `apt-listchanges` |
| Remove telemetry | `apport`, `whoopsie`, `ubuntu-report`, `popularity-contest`, `ubuntu-advantage-tools` (optional), `snapd` (optional) |
| Enable services | `auditd`, `unattended-upgrades` enabled and started |

> **snapd removal** cleans up leftover loop mounts and snap directories. If you rely on any snap packages, pass `--keep-snap`.

> **ubuntu-advantage-tools** (also called `ubuntu-pro-client`) provides access to Ubuntu Pro features but also performs periodic call-home. Pass `--keep-ubuntu-pro` to retain it.

---

### `harden.sh` — System hardening

Run after `provision.sh`. Applies all security controls.

```
Usage: sudo bash harden.sh [OPTIONS]

Options:
  --ssh-port PORT    SSH port to keep open in UFW (default: current sshd port or 22)
  --skip SECTIONS    Comma-separated list of sections to skip
  --dry-run          Show what would be done without making changes
  --help             Show this help
```

**Sections applied:**

| # | Section | What it does |
|---|---|---|
| 1 | `ufw` | UFW default-deny inbound; allows only SSH (on detected or specified port). Enables UFW with `--force`. |
| 2 | `ssh` | Writes hardened `/etc/ssh/sshd_config`. Disables password auth if SSH keys are present, disables root login, sets strong algorithms, enforces `MaxAuthTries 3`, disables X11/agent/TCP forwarding. Backs up existing config before overwriting. |
| 3 | `apparmor` | Enforces AppArmor profiles for all loaded services (`aa-enforce /etc/apparmor.d/*`). Enables `apparmor` service. |
| 4 | `sysctl` | Installs network stack and kernel hardening parameters (see details below). Applied immediately and persisted to `/etc/sysctl.d/`. |
| 5 | `services` | Masks `avahi-daemon` (mDNS), `cups` (printing), `rpcbind` (NFS portmapper), `apport` (crash reporter) |
| 6 | `coredumps` | Disables core dumps via `systemd-coredump` config, PAM limits (`hard core 0`), and `fs.suid_dumpable=0` |
| 7 | `auditd` | Configures audit rules: authentication events, privilege escalation (`sudo`, `su`), file access to `/etc/passwd`/`/etc/shadow`/`/etc/sudoers`, system call monitoring for `execve`. |
| 8 | `updates` | Configures `unattended-upgrades` for automatic security-only patching. Sets `Unattended-Upgrade::Automatic-Reboot "false"` to avoid unexpected reboots. |
| 9 | `pam` | Configures `pam_pwquality` (12+ char passwords, complexity requirements) and `pam_faillock` (10 failed attempts → 15-minute lockout) |
| 10 | `fail2ban` | Configures fail2ban SSH jail: 3 retries, 10-minute ban, watches `/var/log/auth.log`. Enables and starts `fail2ban` service. |

---

## sysctl Settings Applied

Written to `/etc/sysctl.d/90-secure-oss.conf`. Applied immediately and on every boot.

**Network hardening:**

| Parameter | Value | Purpose |
|---|---|---|
| `net.ipv4.conf.all.accept_redirects` | `0` | Block ICMP redirects (MITM prevention) |
| `net.ipv6.conf.all.accept_redirects` | `0` | Same for IPv6 |
| `net.ipv4.conf.all.send_redirects` | `0` | Don't act as a router |
| `net.ipv4.conf.all.accept_source_route` | `0` | Block source-routed packets |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood protection |
| `net.ipv4.conf.all.rp_filter` | `1` | Anti-spoofing (reverse path filtering) |
| `net.ipv4.conf.all.log_martians` | `1` | Log impossible source addresses |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | Ignore broadcast pings (Smurf) |
| `net.ipv4.icmp_ignore_bogus_error_responses` | `1` | Ignore bogus ICMP error responses |

**Kernel hardening:**

| Parameter | Value | Purpose |
|---|---|---|
| `kernel.dmesg_restrict` | `1` | Only root reads kernel ring buffer |
| `kernel.kptr_restrict` | `2` | Hide kernel symbol addresses from all users |
| `kernel.yama.ptrace_scope` | `1` | Restrict ptrace to parent/child only |
| `net.core.bpf_jit_harden` | `2` | Harden BPF JIT (resist JIT spray) |
| `kernel.perf_event_paranoid` | `3` | Restrict perf events to root |
| `vm.mmap_min_addr` | `65536` | Prevent null-pointer-deref exploitation |
| `fs.protected_hardlinks` | `1` | Block TOCTOU hardlink attacks |
| `fs.protected_symlinks` | `1` | Block symlink swap attacks in sticky dirs |
| `fs.suid_dumpable` | `0` | Prevent setuid core dump credential leakage |
| `kernel.unprivileged_userns_clone` | `0` | Disable unprivileged user namespaces (LPE prevention) |

---

## Idempotency

Applied sections are tracked in `/etc/secure_oss/applied/`. Re-running skips already-applied sections.

To force re-application of a section:
```bash
sudo rm /etc/secure_oss/applied/ssh
sudo bash harden.sh --skip ufw,apparmor,sysctl,services,coredumps,auditd,updates,pam,fail2ban
```

All output is logged to `/var/log/secure_oss.log`.

---

## Full Workflow

```bash
# Step 1 — provision packages
sudo bash provision.sh

# Or if you use snap packages:
sudo bash provision.sh --keep-snap

# Step 2 — apply hardening
sudo bash harden.sh

# Step 2a — specify a non-standard SSH port:
sudo bash harden.sh --ssh-port 2222

# Step 3 — verify
ufw status verbose
sshd -T | grep -E 'permitrootlogin|passwordauth|pubkeyauth'
aa-status
systemctl is-active fail2ban
```

---

## Post-Hardening Checklist

```
[ ] Verify SSH access works before ending your current session
[ ] Add additional UFW rules for any services this host exposes:
      ufw allow from 192.168.1.0/24 to any port 443
[ ] Confirm fail2ban is running:
      fail2ban-client status sshd
[ ] Review auditd rules:
      auditctl -l
[ ] Check AppArmor status:
      aa-status
[ ] Confirm unattended-upgrades is configured:
      unattended-upgrades --dry-run --debug 2>&1 | head -30
```

---

## Library: `lib/common.sh`

Sourced by all scripts. Provides shared logging, dry-run support, idempotency markers, and argument parsing.
