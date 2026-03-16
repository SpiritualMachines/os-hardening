# Fedora Silverblue Light — Hardening Instructions

## Overview

This is the **light variant** of the Fedora Silverblue hardening script. It applies the same network hardening, service masking, sysctl tuning, and monitoring as the full Silverblue script, but does **not** install any additional packages via `rpm-ostree`.

This is the right choice when:
- You want to avoid the reboot required by `rpm-ostree install`
- You want to stay on a stock Silverblue/Kinoite image (not secureblue)
- You prefer the minimal footprint of no layered packages

**Compared to full Silverblue (`fedora-silverblue/`):**

| Area | Full Silverblue | Silverblue Light (this) |
|---|---|---|
| Base image | Rebases to secureblue | Stays on stock image |
| Extra packages | `inotify-tools` layered via rpm-ostree | None — no extra packages |
| MDM/RMM monitoring | Real-time via `inotifywait` | Poll-based via SHA-256 checksums (2-minute timer) |
| Kernel hardening | secureblue baked in | Relies on Fedora defaults |
| reboot required | Yes (for rebase) | No |

---

## Prerequisites

- Fedora Silverblue or Kinoite installed (Fedora 40+)
- Root / sudo access
- No internet access required

---

## Script: `harden.sh`

```
Usage: sudo bash harden.sh [OPTIONS]

Options:
  --dns PROVIDER    DNS-over-TLS provider: quad9 | mullvad | both (default: quad9)
  --skip SECTIONS   Comma-separated list of sections to skip
                    Values: firewall, services, sysctl, dhcp, mac, abrt,
                            cockpit, amt, monitor
  --dry-run         Show what would be done without making changes
  --help            Show this help
```

**Sections applied:**

| # | Section | What it does |
|---|---|---|
| 1 | `firewall` | Configures firewalld default-deny inbound (removes all services/ports from default zone) |
| 2 | `services` | Masks Avahi/mDNS, Cockpit socket, ABRT crash reporter |
| 3 | `sysctl` | Network stack and kernel hardening parameters (see details below) |
| 4 | `dhcp` | Suppresses hostname in DHCP requests via NetworkManager config |
| 5 | `mac` | Per-connection MAC address randomization via NetworkManager |
| 6 | `abrt` | Masks all ABRT (Automatic Bug Reporting Tool) units — prevents crash data transmission to Red Hat |
| 7 | `cockpit` | Masks `cockpit.socket` — the web-based admin console |
| 8 | `amt` | Intel ME/AMT OS-layer hardening (see Intel AMT section below) |
| 9 | `monitor` | Deploys MDM/RMM intrusion monitoring (see Monitoring section below) |

---

## Monitoring (poll-based, no extra packages)

Because Silverblue's base is read-only and installing packages requires `rpm-ostree` (plus a reboot), this variant uses a **checksum-based polling** approach instead of inotify.

**How it works:**
- A systemd timer fires every 2 minutes
- SHA-256 checksums of watched files are stored in `/var/lib/secure-oss-light/monitor/`
- On each run, current checksums are compared against the stored baseline
- New systemd units (`.service`, `.timer`, `.socket`) are detected via sorted diff
- Running processes are scanned against a list of known RMM agent names

**Watched files:**
- `/etc/ssh/sshd_config`
- `/etc/sudoers`
- `/root/.ssh/authorized_keys`

**What triggers an alert:**
- Any watched file changes from its baseline checksum
- A new systemd service/timer/socket appears that wasn't present at baseline time
- A known RMM agent process is detected running

**Alert channels:**
- `logger -p security.warning` — written to the systemd journal (searchable via `journalctl -t secure-oss-light`)
- `wall` — broadcast to all TTYs
- `notify-send` — desktop notification to all logged-in sessions via D-Bus

**Known RMM agents detected:** TeamViewer, AnyDesk, Datto RMM, Kaseya, Splashtop, BeyondTrust/Bomgar, Pulseway, NinjaOne, ConnectWise, ScreenConnect, RemotePC, GoTo Resolve, Zoho Assist, Atera, Intel LMS/UNS.

> The detection list covers common commercial tools but is not exhaustive. Extend `RMM_PROCS` in the deployed monitor script to match additional tools relevant to your environment.

**Verification:**
```bash
systemctl status secure-oss-light-monitor.timer
journalctl -t secure-oss-light --since '-24h'
```

---

## Intel ME/AMT Hardening (`amt` section)

Applies OS-layer mitigations for Intel Management Engine and Active Management Technology.

**What is applied:**
- `mei_me` and `mei_wdt` kernel modules blacklisted via `/etc/modprobe.d/` — severs the OS-to-ME communication channel
- Windows Firewall rules blocking AMT ports (TCP 16992–16995, 664 / UDP 623)
- AMT port listener detection added to the regular monitoring scan

**Critical limitation:** AMT in shared-NIC mode intercepts packets at the NIC firmware level, before the OS network stack or firewall. Host-level firewall rules are **not effective** against AMT.

**Recommended mitigation:** Block AMT ports on your **gateway/router** — an upstream device that is physically separate from the NIC:
```
TCP: 16992, 16993, 16994, 16995, 664
UDP: 623
```

For full LAN-level protection (guards against same-subnet attackers that bypass the gateway), use **VLAN isolation** with inter-VLAN rules blocking the above ports.

**Verification:**
```bash
lsmod | grep mei          # should show nothing if blacklist applied after reboot
ss -tlnp | grep -E ':16992|:16993|:16994|:16995'   # should show nothing
```

---

## sysctl Settings Applied

Written to `/etc/sysctl.d/90-secure-oss-light.conf`. Applied immediately and on every boot.

**Network hardening:**

| Parameter | Value | Purpose |
|---|---|---|
| `net.ipv4.conf.all.accept_redirects` | `0` | Block ICMP redirects (MITM prevention) |
| `net.ipv4.conf.all.send_redirects` | `0` | Don't act as a router |
| `net.ipv4.conf.all.accept_source_route` | `0` | Block source-routed packets |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood protection |
| `net.ipv4.conf.all.rp_filter` | `1` | Anti-spoofing (reverse path filtering) |
| `net.ipv4.conf.all.log_martians` | `1` | Log impossible source addresses |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | Ignore broadcast pings (Smurf) |

**Kernel hardening:**

| Parameter | Value | Purpose |
|---|---|---|
| `kernel.dmesg_restrict` | `1` | Only root reads kernel ring buffer |
| `kernel.kptr_restrict` | `1` | Hide kernel symbol addresses |
| `net.core.bpf_jit_harden` | `2` | Harden BPF JIT (resist JIT spray) |
| `kernel.yama.ptrace_scope` | `1` | Restrict ptrace to parent/child only |
| `kernel.perf_event_paranoid` | `3` | Restrict perf events to root |
| `vm.mmap_min_addr` | `65536` | Prevent null-pointer-deref exploitation |
| `fs.protected_hardlinks` | `1` | Block TOCTOU hardlink attacks |
| `fs.protected_symlinks` | `1` | Block symlink swap attacks in sticky dirs |
| `fs.suid_dumpable` | `0` | Prevent setuid core dump credential leakage |
| `kernel.unprivileged_userns_clone` | `0` | Disable unprivileged user namespaces (LPE prevention) |

---

## Idempotency

Applied sections are tracked in `/etc/secure_oss/applied/`. Re-running the script skips already-applied sections. To re-apply a section:

```bash
sudo rm /etc/secure_oss/applied/firewall
sudo bash harden.sh --skip services,sysctl,dhcp,mac,abrt,cockpit,amt,monitor
```

All output is logged to `/var/log/secure_oss.log`.

---

## Full Workflow

```bash
# Preview changes without applying
sudo bash harden.sh --dry-run

# Apply all hardening
sudo bash harden.sh

# Apply with Mullvad DNS
sudo bash harden.sh --dns mullvad

# Skip monitoring (if you don't want the timer)
sudo bash harden.sh --skip monitor

# Verify firewall
firewall-cmd --list-all

# Verify monitoring timer
systemctl status secure-oss-light-monitor.timer

# Check for alerts in the last 24 hours
journalctl -t secure-oss-light --since '-24h'
```

---

## Silverblue-Specific Notes

- `/usr` is read-only (ostree managed) — all configs go to `/etc` or `/var`
- The monitor state directory is `/var/lib/secure-oss-light/monitor/` — persists across sessions, cleared on OS reinstall
- `restorecon` is called after file writes to maintain correct SELinux contexts
- All monitoring infrastructure is written to `/etc/systemd/system/` (writable on Silverblue) and `/usr/local/lib/secure-oss-light/`
