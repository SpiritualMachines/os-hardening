# Ubuntu Desktop — Provisioning & Hardening Instructions

## Overview

These scripts apply a practical security baseline to Ubuntu Desktop 22.04 LTS or 24.04 LTS (GNOME). The workflow is split into two stages:

1. **`provision.sh`** — Installs required security packages and removes Ubuntu telemetry. Run once on a fresh installation.
2. **`harden.sh`** — Applies all hardening. Safe to re-run at any time (idempotent).

---

## Prerequisites

- Ubuntu Desktop 22.04 LTS or 24.04 LTS
- Root / sudo access
- Internet access (for `provision.sh`)
- Run `provision.sh` before `harden.sh`

---

## Scripts

### `provision.sh` — Package installation and telemetry removal

Run first. Updates apt, installs security tools, and removes Ubuntu telemetry packages.

```
Usage: sudo bash provision.sh [OPTIONS]

Options:
  --remove-snap       Remove snapd and all snap packages.
                      WARNING: Ubuntu Desktop ships Firefox as a snap by default.
                      Removing snapd will also remove Firefox. Install the
                      Mozilla PPA deb or another browser first. See snap note below.
  --keep-ubuntu-pro   Do not remove ubuntu-advantage-tools / ubuntu-pro-client
  --dry-run           Show what would be done without making changes
  --help              Show this help
```

**What it does:**

| Step | Details |
|---|---|
| apt update | Refreshes package lists |
| Install packages | `ufw`, `auditd`, `audispd-plugins`, `libpam-pwquality`, `unattended-upgrades`, `apt-listchanges`, `apparmor-utils`, `dconf-cli` |
| Remove telemetry | `apport`, `apport-symptoms`, `whoopsie`, `kerneloops`, `ubuntu-report`, `popularity-contest`, `ubuntu-advantage-tools` (optional), `snapd` (optional, off by default) |
| Enable services | `auditd` enabled and started |
| Enable auto-upgrades | `unattended-upgrades` pre-configured |

> **snapd removal** is opt-in via `--remove-snap`. Ubuntu Desktop ships Firefox as a snap by default. Removing snapd without first installing a replacement browser (e.g. via the Mozilla PPA) will leave you without a browser. To install the deb version of Firefox before removing snap:
> ```bash
> add-apt-repository ppa:mozillateam/ppa
> apt-get install -t 'o=LP-PPA-mozillateam' firefox
> sudo bash provision.sh --remove-snap
> ```

> **ubuntu-advantage-tools** (also called `ubuntu-pro-client`) performs periodic call-home to Canonical's contract servers. Pass `--keep-ubuntu-pro` to retain it if you use Ubuntu Pro features.

---

### `harden.sh` — System hardening

Run after `provision.sh`. Applies all security controls.

```
Usage: sudo bash harden.sh [OPTIONS]

Options:
  --skip SECTIONS   Comma-separated list of sections to skip
  --mask-cups       Also mask cups.service (disables printing)
  --dry-run         Show what would be done without making changes
  --help            Show this help
```

**Sections applied:**

| # | Section | What it does |
|---|---|---|
| 1 | `ufw` | UFW default-deny inbound; outbound allowed. No SSH port opened by default (desktop does not ship openssh-server). Enables UFW with `--force`. |
| 2 | `apparmor` | Enforces AppArmor profiles for all loaded services (`aa-enforce /etc/apparmor.d/*`). Reloads AppArmor service. |
| 3 | `sysctl` | Copies `lib/sysctl-hardening.conf` to `/etc/sysctl.d/90-secure-oss.conf` and applies immediately. See sysctl table below. |
| 4 | `services` | Masks: `whoopsie`, `kerneloops`, `apport`, `geoclue`, `gnome-remote-desktop`, `tracker-miner-fs-3`, `tracker-miner-rss-3`, `cups-browsed`. Optionally masks `cups` if `--mask-cups` is passed. |
| 5 | `ssh` | **Only applies if openssh-server is installed.** Writes hardened `/etc/ssh/sshd_config.d/90-secure-oss.conf`. Disables password auth if SSH keys are present. Adds UFW allow rule for the SSH port. |
| 6 | `coredumps` | Disables core dumps via systemd coredump config, PAM limits (`hard core 0`), and `fs.suid_dumpable=0`. |
| 7 | `auditd` | Configures audit rules: authentication events, privilege escalation (`sudo`, `su`), sensitive file access, network config changes, kernel module loading. |
| 8 | `updates` | Configures `unattended-upgrades` for automatic security-only patching. Does not auto-reboot on desktop. |
| 9 | `pam` | Configures `pam_pwquality` (14+ char passwords, complexity requirements) and `pam_faillock` (5 failed attempts → 10-minute lockout). |
| 10 | `telemetry` | Blocks Ubuntu/Canonical telemetry domains in `/etc/hosts`. Disables `motd-news.timer`. Writes NetworkManager config to disable connectivity checks. Masks `ubuntu-report` if present. |
| 11 | `mdm` | Blocks MDM/RMM domains in `/etc/hosts`. Masks `landscape-client.service` if present. |
| 12 | `gnome` | Sources `lib/gnome.sh`. Masks GNOME remote desktop, GeoClue, tracker miners, whoopsie, kerneloops, apport. Applies gsettings for the calling user (privacy, lock screen, notifications). Writes dconf system locks. |

---

## sysctl Settings Applied

Written to `/etc/sysctl.d/90-secure-oss.conf` from `lib/sysctl-hardening.conf`. Applied immediately and on every boot.

**Network hardening:**

| Parameter | Value | Purpose |
|---|---|---|
| `net.ipv4.tcp_syncookies` | `1` | SYN flood protection |
| `net.ipv4.tcp_rfc1337` | `1` | Time-wait assassination attack prevention |
| `net.ipv4.tcp_timestamps` | `0` | Disable remote clock fingerprinting |
| `net.ipv4.icmp_echo_ignore_all` | `1` | Ignore ping (reduces network reconnaissance) |
| `net.ipv4.conf.all.accept_redirects` | `0` | Block ICMP redirects (MITM prevention) |
| `net.ipv6.conf.all.accept_redirects` | `0` | Same for IPv6 |
| `net.ipv4.conf.all.send_redirects` | `0` | Don't act as a router |
| `net.ipv4.conf.all.accept_source_route` | `0` | Block source-routed packets |
| `net.ipv4.conf.all.rp_filter` | `1` | Anti-spoofing (reverse path filtering) |
| `net.ipv4.conf.all.log_martians` | `1` | Log impossible source addresses |
| `net.ipv4.conf.all.drop_gratuitous_arp` | `1` | Prevent ARP cache poisoning |
| `net.ipv6.conf.all.use_tempaddr` | `2` | IPv6 privacy addresses (prefer temporary) |
| `net.ipv6.conf.all.accept_ra` | `0` | Reject IPv6 router advertisements |

**Kernel hardening:**

| Parameter | Value | Purpose |
|---|---|---|
| `kernel.dmesg_restrict` | `1` | Only root reads kernel ring buffer |
| `kernel.kptr_restrict` | `2` | Hide kernel symbol addresses from all users |
| `kernel.yama.ptrace_scope` | `1` | Restrict ptrace to parent/child only |
| `kernel.sysrq` | `0` | Disable magic SysRq key |
| `kernel.unprivileged_bpf_disabled` | `1` | Restrict unprivileged eBPF |
| `net.core.bpf_jit_harden` | `2` | Harden BPF JIT (resist JIT spray) |
| `kernel.perf_event_paranoid` | `3` | Restrict perf events to root |
| `kernel.kexec_load_disabled` | `1` | Disable kexec (kernel replacement) |
| `kernel.core_pattern` | `\|/bin/false` | Suppress core dump creation |
| `fs.suid_dumpable` | `0` | Prevent setuid core dump credential leakage |
| `fs.protected_fifos` | `2` | Block FIFO-based privilege escalation in sticky dirs |
| `fs.protected_regular` | `2` | Block regular file-based privilege escalation |
| `fs.protected_symlinks` | `1` | Block symlink swap attacks |
| `fs.protected_hardlinks` | `1` | Block TOCTOU hardlink attacks |
| `vm.mmap_rnd_bits` | `32` | Improve ASLR entropy |
| `vm.mmap_min_addr` | `65536` | Prevent null-pointer-deref exploitation |
| `vm.unprivileged_userfaultfd` | `0` | Disable unprivileged userfaultfd (LPE prevention) |
| `dev.tty.ldisc_autoload` | `0` | Restrict TTY line discipline autoloading |

> **Note:** `kernel.unprivileged_userns_clone` is intentionally absent. Ubuntu 24.04 removed this sysctl. Chrome, Electron apps, and container runtimes require unprivileged user namespaces. Ubuntu 24.04 ships AppArmor restrictions that limit userns creation instead.

---

## Idempotency

Applied sections are tracked in `/etc/secure_oss/applied/`. Re-running skips already-applied sections.

To force re-application of a specific section:
```bash
sudo rm /etc/secure_oss/applied/gnome
sudo bash harden.sh --skip ufw,apparmor,sysctl,services,ssh,coredumps,auditd,updates,pam,telemetry,mdm
```

All output is logged to `/var/log/secure_oss.log`.

---

## Full Workflow

```bash
# Step 1 — provision packages
sudo bash provision.sh

# Step 1 (alternate) — if you want to remove snap (read the Firefox warning first):
# Install Mozilla PPA Firefox before removing snap
sudo add-apt-repository ppa:mozillateam/ppa
sudo apt-get install -t 'o=LP-PPA-mozillateam' firefox
sudo bash provision.sh --remove-snap

# Step 2 — apply hardening
sudo bash harden.sh

# Step 2a — apply hardening but keep printing enabled (default) and skip GNOME
#           if running from a TTY (not a desktop session):
sudo bash harden.sh --skip gnome

# Step 2b — disable printing as well:
sudo bash harden.sh --mask-cups

# Step 3 — re-apply GNOME settings from a running desktop session:
sudo bash harden.sh --skip ufw,apparmor,sysctl,services,ssh,coredumps,auditd,updates,pam,telemetry,mdm

# Step 4 — verify
ufw status verbose
aa-status
auditctl -l
grep connectivity-check.ubuntu.com /etc/hosts
gsettings get org.gnome.desktop.privacy report-technical-problems
systemctl is-enabled gnome-remote-desktop.service whoopsie.service
```

---

## Post-Hardening Checklist

```
[ ] Reboot to apply all sysctl and kernel settings
[ ] Verify UFW is active:
      ufw status verbose
[ ] Check AppArmor enforcement:
      aa-status
[ ] Verify audit rules are loaded:
      auditctl -l
[ ] Confirm telemetry domains are blocked:
      grep connectivity-check.ubuntu.com /etc/hosts
      grep manage.microsoft.com /etc/hosts
[ ] Confirm GNOME privacy settings:
      gsettings get org.gnome.desktop.privacy report-technical-problems
      gsettings get org.gnome.desktop.privacy remember-recent-files
      gsettings get org.gnome.system.location enabled
[ ] Confirm crash reporters are masked:
      systemctl is-enabled whoopsie.service
      systemctl is-enabled apport.service
      systemctl is-enabled gnome-remote-desktop.service
[ ] Confirm unattended-upgrades is configured:
      unattended-upgrades --dry-run --debug 2>&1 | head -30
[ ] If openssh-server was hardened, verify SSH still works:
      sshd -T | grep -E 'permitrootlogin|passwordauthentication|pubkeyauthentication'
```

---

## Library: `lib/common.sh`

Sourced by all scripts. Provides shared logging, dry-run support, idempotency markers, argument parsing, desktop environment detection (`detect_desktop_environment`), and sudo user resolution (`get_sudo_user` / `run_as_user`).

## Library: `lib/gnome.sh`

Sourced by `harden.sh` when the `gnome` section runs. Provides `harden_gnome` which calls three functions: `gnome_harden_services`, `gnome_harden_user_settings`, and `gnome_apply_dconf_locks`.
