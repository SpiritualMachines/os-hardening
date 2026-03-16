# Unraid — Provisioning & Hardening Instructions

## Overview

Unraid's security posture is unusual compared to a standard Linux distribution:

- The OS runs **entirely in RAM** from a USB flash drive. The base OS resets on every reboot.
- **Persistent configuration lives in `/boot/config/`** on the USB drive. Anything that must survive a reboot must be written there.
- **`/boot/config/go`** is a shell script that runs on every boot after the array starts. It is the primary hook for all persistent hardening.
- Unraid ships with **no firewall configured** by default. iptables is available (Linux kernel), but no rules are applied out of the box.

---

## Threat Model

This hardening addresses two distinct threat scenarios:

### External threats (network attackers)
- Unauthorized access to the Unraid web UI, Samba shares, or SSH from the network
- Port scanning and service enumeration
- Brute force attacks against SSH or SMB

### Internal threats (malicious content on disk)
Relevant when using the array to **store malware samples, forensic disk images, or incident artifacts**:
- Files being accidentally executed by the OS or a service
- Services that automatically parse files (media servers, thumbnail generators, file indexers) being exploited via crafted content
- Docker containers with volume mounts to the forensics share being compromised via the files they can read
- Symlink-based path traversal attacks from malicious filenames in the share
- Local privilege escalation via kernel vulnerabilities (mitigated by kernel hardening parameters)

---

## Scripts

### `harden.sh` — Core hardening

Run as root. Does not require a reboot to take effect (all changes apply immediately and persist via `/boot/config/go`).

```bash
sudo bash harden.sh [OPTIONS]
```

**Options:**

| Option | Description |
|---|---|
| `--local-subnet CIDR` | Subnet for firewall rules (default: auto-detected, e.g. `192.168.1.0/24`) |
| `--ssh-port PORT` | SSH port (default: auto-detected from running sshd, or 22) |
| `--web-http-port PORT` | Unraid web UI HTTP port (default: read from `/boot/config/ident.cfg`) |
| `--web-https-port PORT` | Unraid web UI HTTPS port (default: read from `ident.cfg`) |
| `--wireguard-port PORT` | WireGuard UDP port to open inbound (default: auto-detected if WireGuard is active) |
| `--allow-nfs` | Open NFS ports (2049, 111) from local subnet (default: blocked) |
| `--no-smb` | Block SMB ports (default: SMB is allowed from local subnet) |
| `--block-cloud` | Block Unraid.net / myservers call-home (see Cloud section below) |
| `--skip SECTIONS` | Comma-separated sections to skip: `firewall,ssh,sysctl,cloud` |
| `--dry-run` | Show what would be done without making changes |

**Sections applied:**

| # | Section | What it does |
|---|---|---|
| 1 | `firewall` | Deploys iptables host firewall. Default-deny inbound. Opens web UI, SSH, and optionally SMB/NFS/WireGuard from local subnet only. Leaves FORWARD chain untouched for Docker/VMs. Restricts Docker container ports to local subnet via DOCKER-USER chain. |
| 2 | `ssh` | Writes hardened `sshd_config` to `/boot/config/ssh/` (persists across reboots). Key-only auth if SSH keys are detected, no root login, strong algorithms only. |
| 3 | `sysctl` | Network stack hardening (ICMP redirect/source route blocking, SYN cookies, rp_filter) **plus internal threat mitigations** (see below). Written to `/boot/config/secure_oss/` and re-applied on every boot via go hook. |
| 4 | `cloud` | *(opt-in via `--block-cloud`)* Null-routes Unraid.net cloud endpoints in `/etc/hosts` via go hook. Disables Unraid Connect dashboard. |

#### Kernel parameters applied by `sysctl` section

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
| `kernel.dmesg_restrict` | `1` | Only root reads kernel ring buffer |
| `kernel.kptr_restrict` | `1` | Hide kernel symbol addresses |
| `net.core.bpf_jit_harden` | `2` | Harden BPF JIT (resist JIT spray) |

**Internal threat / local privilege escalation hardening:**

| Parameter | Value | Purpose |
|---|---|---|
| `kernel.unprivileged_userns_clone` | `0` | Disable unprivileged user namespaces — the most commonly exploited kernel feature in container escapes and LPE CVEs. Docker (rootful) is unaffected. |
| `kernel.yama.ptrace_scope` | `1` | Restrict ptrace to parent/child only. Prevents one process from reading another process's memory. |
| `kernel.perf_event_paranoid` | `3` | Restrict perf events to root. Perf data can be used for side-channel attacks (Spectre variants). |
| `vm.mmap_min_addr` | `65536` | Prevent userspace from mapping address 0x0. Turns a kernel null-pointer-deref from a crash into an exploitable condition — this closes that path. |
| `fs.protected_hardlinks` | `1` | Prevent hardlinks to files the user doesn't own. Blocks a class of TOCTOU privilege escalation attacks. |
| `fs.protected_symlinks` | `1` | Prevent symlink following in world-writable sticky directories (e.g. `/tmp`). Blocks classic symlink swap attacks. |
| `fs.suid_dumpable` | `0` | Prevent setuid/setgid programs from creating core dumps. Stops credential/key leakage via dump files. |

---

### `optional/forensics-share.sh` — Forensic and incident response storage hardening

Use this when the Unraid array is used to **store malware samples, forensic disk images, or artifacts from security incidents**. This script locks down a specific named share to contain malicious content and prevent it from being executed or exploited by the host OS or its services.

```bash
sudo bash optional/forensics-share.sh --share <NAME> [OPTIONS]
```

**Options:**

| Option | Description |
|---|---|
| `--share NAME` | Unraid share name to protect (e.g. `forensics`, `malware-samples`). Must already exist in the Unraid UI. |
| `--read-only` | Mount with `ro` in addition to `noexec,nosuid,nodev`. Use when you only need to read/analyse files, never write new ones via the local filesystem. |
| `--dry-run` | Show what would be done without making changes |

**What it applies:**

#### 1. noexec bind mount

The share is bind-mounted over itself with `noexec,nosuid,nodev`. The Linux kernel enforces this at the VFS layer:

- **`noexec`** — The kernel refuses to `execve()` any file from this mount, regardless of the file's permission bits or who is asking. Even root cannot execute a file from a `noexec` mount without explicitly remounting it. This is the primary protection against accidental or service-triggered execution of malware.
- **`nosuid`** — Ignores setuid/setgid bits on executables. A malicious setuid binary in the share cannot be used to escalate privileges even if somehow executed via another mechanism.
- **`nodev`** — Ignores device node files. A crafted device node in the share cannot be used to access raw hardware.

The mount is persisted via a boot script in `/boot/config/scripts/` that re-applies it after the array starts on every reboot.

**Testing the noexec mount:**
```bash
cp /bin/ls /mnt/user/<share>/test_exec
/mnt/user/<share>/test_exec   # should fail: Permission denied
rm /mnt/user/<share>/test_exec
```

#### 2. Samba share hardening

The Samba configuration for the share is patched (via a post-start hook) with:

| Setting | Purpose |
|---|---|
| `follow symlinks = no` | Samba will not follow any symlinks within the share. A malicious symlink named `shadow` pointing to `/etc/shadow` cannot be read by a Samba client. |
| `wide links = no` | Samba will not follow symlinks that point outside the share root. Without this, a symlink could expose any file on the host filesystem to network clients. |
| `read only = yes` | *(if `--read-only`)* Prevents all write operations via Samba at the protocol level. |

Global Samba hardening is also applied to `/boot/config/smb-extra.conf`:
- `ntlm auth = no` — Disables NTLMv1 (relay attack prevention). Clients must use NTLMv2 or Kerberos.
- `server min protocol = SMB2` — Disables SMBv1.

#### 3. Docker container audit

Scans all Docker containers (running and stopped) for volume mounts that include the forensics share path. **Does not make changes** — reports findings for manual review.

Why this matters: Docker container ports exposed via `-p` bypass the `INPUT` chain and go through `FORWARD/DOCKER` chains. A container with a volume mount to the forensics share can read (and be exploited by) malicious files even if the host firewall is tight. The audit identifies which containers have this access so you can evaluate and update their mounts.

#### 4. Media server exclusion markers

Creates marker files that instruct common media servers not to index the share:

| File | Effect |
|---|---|
| `.plexignore` | Tells Plex Media Server to ignore all files in this directory |
| `.ignore` | Tells Jellyfin and Emby to skip this directory |
| `.nomedia` | Tells Android MTP and many generic media scanners to skip this directory |

> **Important:** These markers are a fallback only. The correct action is to ensure the forensics share is **never configured as a library path** in any media server application. Media parsers (FFmpeg, libheif, libraw, libexif, etc.) have a well-documented history of exploitable parser vulnerabilities triggered by crafted files.

#### 5. Filesystem permissions

Sets `root:root` ownership and `750` mode on the share root, and removes world-readable/executable bits from all existing content recursively. This prevents the `nobody` user (used by Samba guest access and some containers) from accessing the share without explicit permission.

---

## The Docker / DOCKER-USER Chain Explained

Unraid's firewall (`iptables.sh`) manages only the `INPUT` chain — traffic destined for the Unraid host itself. Docker manages the `FORWARD` and `DOCKER` chains independently.

```
Internet → [FORWARD chain] → DOCKER chain → container
Internet → [INPUT chain]   → Unraid host
```

If a Docker container exposes a port with `-p 8080:80`, traffic to port 8080 goes through `FORWARD → DOCKER`, **not through INPUT**. The INPUT firewall does not see it.

The `DOCKER-USER` chain is Docker's designated extension point — rules added here run *before* Docker's own rules and apply to all forwarded traffic. The `iptables.sh` script adds rules to `DOCKER-USER` that drop forwarded traffic from outside the local subnet, closing this gap.

To verify:
```bash
iptables -L DOCKER-USER -n -v
```

---

## What the `--block-cloud` Option Does

Unraid's "Connect" feature and the `dynamix.my.servers` plugin communicate with Unraid's cloud infrastructure (`unraid.net`, `connect.myunraid.net`, `keys.unraid.net`, etc.) for:
- Remote management dashboard
- License validation
- Usage telemetry

With `--block-cloud`, these domains are null-routed in `/etc/hosts` (added via a go hook so the entries persist across reboots). **The Unraid Connect dashboard will stop working.** All local functionality — shares, Docker, VMs, the local web UI — is completely unaffected.

To undo: remove `/boot/config/secure_oss/hosts-unraid-cloud.txt` and remove the corresponding line from `/boot/config/go`, then reboot.

---

## Persistence Model

Because the Unraid OS reloads from USB on every boot, all hardening must re-apply itself. This is handled transparently:

| What | Where it's stored | How it persists |
|---|---|---|
| Firewall rules | `/boot/config/scripts/iptables.sh` | Called from `/boot/config/go` on boot |
| SSH config | `/boot/config/ssh/sshd_config` | Copied to `/etc/ssh/` by Unraid on boot (6.10+) |
| sysctl params | `/boot/config/secure_oss/sysctl-hardening.conf` | `sysctl -p <file>` called from go on boot |
| Cloud block | `/boot/config/secure_oss/hosts-unraid-cloud.txt` | Appended to `/etc/hosts` from go on boot |
| noexec mount | `/boot/config/scripts/forensics-noexec-<share>.sh` | Called from go (delayed 30s for array start) |
| Samba patch | `/boot/config/scripts/forensics-samba-<share>.sh` | Called from go (delayed 45s for Samba start) |

All go hooks use unique comment markers so they can be added idempotently and removed cleanly.

---

## Full Workflow

```bash
# Step 1 — run core hardening (auto-detects most settings)
sudo bash harden.sh

# Or with explicit options:
sudo bash harden.sh --local-subnet 192.168.10.0/24 --ssh-port 2222

# Step 2 — verify firewall
iptables -L INPUT -n -v
iptables -L DOCKER-USER -n -v

# Step 3 — if you store forensic/malware data on this array:
sudo bash optional/forensics-share.sh --share forensics

# If the share is read-only analysis storage:
sudo bash optional/forensics-share.sh --share malware-samples --read-only

# Step 4 — verify noexec
cp /bin/ls /mnt/user/forensics/test_exec
/mnt/user/forensics/test_exec   # should fail
rm /mnt/user/forensics/test_exec
```

---

## Limitations and What This Does Not Cover

| Limitation | Notes |
|---|---|
| **noexec is not a sandbox** | noexec prevents execution via `execve()`. A running process can still `read()` a file and interpret it as code (e.g. Python running a script it reads). Don't run interpreters pointed at the forensics share. |
| **Root can bypass noexec** | Root can `mount --bind -o remount,exec` to remove noexec. The protection is against accidents and service exploitation, not against a compromised root. |
| **Disk image analysis** | If you mount raw disk images from the forensics share (e.g. `mount -o loop image.dd /mnt/evidence`), the filesystem driver parses the image. Crafted filesystem metadata has triggered kernel bugs. Do this in a VM instead. |
| **Kernel filesystem vulnerabilities** | The XFS/btrfs driver reading a crafted filesystem is outside the scope of these scripts. Use a VM for anything requiring filesystem-level parsing of untrusted images. |
| **AppArmor / SELinux** | Unraid does not ship with MAC (mandatory access control). All access control is DAC (permissions + noexec). |
