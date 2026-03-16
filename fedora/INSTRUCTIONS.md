# Fedora Workstation & KDE Plasma — Provisioning & Hardening Instructions

## Overview

These scripts harden a standard (mutable) Fedora installation — both
**Fedora Workstation (GNOME)** and **Fedora KDE Plasma** — using a single shared
set of scripts. The desktop environment is detected automatically and
DE-specific hardening is applied accordingly.

Unlike the Silverblue scripts (which rebase to a pre-hardened OCI image),
these scripts build the full hardening stack from scratch: kernel arguments,
sysctl settings, module blacklisting, firewall, DNS, services, and
DE-specific privacy settings.

---

## How DE Detection Works

`harden.sh` detects the desktop environment at runtime:

1. Checks `$XDG_CURRENT_DESKTOP` and `$DESKTOP_SESSION` environment variables
2. Falls back to checking installed packages (`gnome-shell` or `plasma-desktop`)
3. Sets `DE=gnome` or `DE=kde` and sources the appropriate lib file
4. If detection fails, DE-specific hardening is skipped with a warning

**Best practice:** Run `harden.sh` with `sudo` from within your desktop session
so that environment variables are inherited correctly.

---

## Scripts

### `provision.sh` — Package management and tooling

Run first. Hardens DNF, updates the system, installs security tools, and
removes telemetry packages.

```
Usage: sudo bash provision.sh [OPTIONS]

Options:
  --skip-update   Skip the full system update (faster for re-runs)
  --dry-run       Show what would be done without making changes
  --help          Show this help
```

**What it does:**

| Step | Details |
|---|---|
| DNF hardening | Sets `gpgcheck=1`, `localpkg_gpgcheck=1`, `clean_requirements_on_remove=True`, `best=True` |
| System update | `dnf upgrade --refresh` |
| Install packages | `usbguard`, `usbguard-notifier`, `audit`, `aide`, `wireguard-tools`, `dnf-automatic`, `nftables`, `chrony` |
| Remove packages | `abrt` and all abrt-\* packages, `telnet`, `rsh`, `ypbind`, `yp-tools`, `tftp`, `talk` |
| Auto-updates | Configures `dnf-automatic` for automatic security updates (daily) |
| auditd | Enables the Linux audit daemon |
| AIDE | Initializes the file integrity monitoring database |

---

### `harden.sh` — System hardening

Run after `provision.sh`. Applies all hardening. Detects GNOME or KDE and
applies DE-specific settings automatically.

```
Usage: sudo bash harden.sh [OPTIONS]

Options:
  --dns PROVIDER    DNS-over-TLS provider: quad9 | mullvad | both (default: quad9)
  --skip SECTIONS   Comma-separated list of sections to skip
  --dry-run         Show what would be done without making changes
  --help            Show this help
```

**Sections applied:**

| # | Section | What it does |
|---|---|---|
| 1 | `kernel` | Applies kernel hardening arguments via `grubby` (PTI, Spectre, IOMMU, memory init, stack randomization, RNG hardening) |
| 2 | `sysctl` | Installs `/etc/sysctl.d/90-secure-oss.conf` with network and kernel hardening; applies immediately |
| 3 | `modules` | Installs module blacklist to `/etc/modprobe.d/`; regenerates initramfs via `dracut` |
| 4 | `selinux` | Verifies SELinux is Enforcing; sets in `/etc/selinux/config` |
| 5 | `firewall` | Configures firewalld default-deny inbound (removes all services/ports from default zone) |
| 6 | `ssh` | If sshd is installed but not enabled: masks it. If enabled: applies hardened drop-in (key-only auth, no root login, strong algorithms) |
| 7 | `dns` | Configures `systemd-resolved` with DNS-over-TLS + DNSSEC |
| 8 | `dhcp` | Suppresses hostname in DHCP requests via NetworkManager |
| 9 | `mac` | Per-connection MAC address randomization via NetworkManager |
| 10 | `usbguard` | Generates USBGuard policy from connected devices, enables service |
| 11 | `mdm` | Null-routes ~50 MDM/RMM domains in `/etc/hosts` |
| 12 | `telemetry` | Null-routes telemetry/crash reporting endpoints in `/etc/hosts` |
| 13 | `services` | Masks ABRT, Avahi/mDNS, Cockpit |
| 14 | `de` | GNOME or KDE-specific hardening (see below) |
| 15 | `coredumps` | Disables core dumps via systemd and PAM limits |
| 16 | `auth` | Configures `faillock` (10 attempts, 15min lockout) and `pwquality` (12+ char passwords) |

---

## Desktop Environment Hardening

### GNOME (`lib/gnome.sh`)

**System-level (applied as root):**
- Masks `gnome-remote-desktop.service` (RDP/VNC)
- Masks `geoclue.service` (location services)
- Masks Tracker miner services (file indexer)
- Writes dconf system policy locks (`/etc/dconf/db/local.d/`)

**User-level (applied via `sudo -u $USER`):**
- Disables location services
- Disables automatic problem/crash reporting
- Disables usage statistics
- Disables recent files history
- Disables remote desktop at user settings level
- Sets screen lock (5 min idle, lock on blank)
- Hides notification content on lock screen

### KDE Plasma (`lib/kde.sh`)

**System-level (applied as root):**
- Masks `krfb.service` / `krfb.socket` (KDE VNC/desktop sharing)
- Masks `geoclue.service` (location services)
- Globally disables `baloo_file.service` (file indexer)

**User-level (applied via `sudo -u $USER`):**
- Sets KDE UserFeedback level to 0 (no telemetry)
- Disables KDE Connect daemon (opens local port, shares clipboard)
- Disables Baloo file indexer via `balooctl`
- Sets screen lock (5 min idle)
- Disables location/GPS in Plasma
- Disables activity/recent file scoring
- Limits Klipper clipboard history to 1 item (no persistent history)

---

### `optional/disable-webcam.sh`

Blacklists the `uvcvideo` kernel module.

> **Warning:** Breaks all UVC webcam access including video conferencing.

```bash
sudo bash optional/disable-webcam.sh          # disable
sudo bash optional/disable-webcam.sh --enable  # re-enable
```

### `optional/bash-lockdown.sh`

Makes shell config files immutable with `chattr +i`.

> **Warning:** Breaks installer tools (rustup, nvm, conda, etc.)

```bash
sudo bash optional/bash-lockdown.sh [--user USERNAME]
sudo bash optional/bash-lockdown.sh --unlock [--user USERNAME]
```

### `optional/wireguard-killswitch.sh`

Generates a WireGuard config with kill-switch (blocks all non-VPN traffic
when tunnel is active).

```bash
sudo bash optional/wireguard-killswitch.sh [--interface wg0]
# Edit /etc/wireguard/wg0.conf with provider details, then:
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

---

## Full Workflow

```bash
# Step 1 — provision packages
sudo bash provision.sh

# Step 2 — reboot (recommended, picks up kernel updates)
systemctl reboot

# Step 3 — run from your desktop session (needed for DE detection)
sudo bash harden.sh

# Step 3a — use Mullvad DNS:
sudo bash harden.sh --dns mullvad

# Step 3b — skip USBGuard if no USB input devices connected:
sudo bash harden.sh --skip usbguard

# Step 4 — preview changes first:
sudo bash harden.sh --dry-run

# Step 5 — reboot to apply kernel args and module blacklist
systemctl reboot
```

---

## Library Files

| File | Purpose |
|---|---|
| `lib/common.sh` | Shared utilities: logging, dry-run, guards, idempotency, DE detection |
| `lib/gnome.sh` | GNOME-specific hardening functions |
| `lib/kde.sh` | KDE Plasma-specific hardening functions |
| `lib/sysctl-hardening.conf` | Installed to `/etc/sysctl.d/90-secure-oss.conf` |
| `lib/modprobe-blacklist.conf` | Installed to `/etc/modprobe.d/secure-oss-blacklist.conf` |
| `lib/hosts-mdm.txt` | MDM/RMM domain blocklist |
| `lib/hosts-telemetry.txt` | Telemetry/analytics domain blocklist |

---

## Kernel Arguments Applied

Applied via `grubby --update-kernel=ALL`. Take effect after reboot.

| Argument | Purpose |
|---|---|
| `pti=on` | Page Table Isolation — Meltdown mitigation |
| `spectre_v2=on` | Spectre v2 mitigation |
| `spec_store_bypass_disable=on` / `ssbd=force-on` | Speculative Store Bypass mitigation |
| `intel_iommu=on` / `amd_iommu=on` | Enable IOMMU for DMA attack prevention |
| `iommu=force` / `iommu.strict=1` | Strict IOMMU mapping enforcement |
| `init_on_alloc=1` / `init_on_free=1` | Zero memory on alloc/free — mitigates UAF |
| `randomize_kstack_offset=on` | Randomize kernel stack on each syscall |
| `page_alloc.shuffle=1` | Shuffle free page lists — improves ASLR |
| `random.trust_bootloader=off` / `random.trust_cpu=off` | Don't seed RNG from potentially controlled sources |
| `proc_mem.force_override=ptrace` | Restrict /proc/pid/mem to ptrace-capable processes |
| `rd.shell=0` | Disable initramfs emergency shell |
| `loglevel=0` | Suppress kernel log to console |
| `systemd.ssh_auto=no` | Disable systemd emergency SSH socket |

**Not applied** (unlike secureblue, these are too aggressive for a desktop):
- `lockdown=confidentiality` — breaks NVIDIA drivers, VirtualBox, some hardware
- `module.sig_enforce=1` — breaks unsigned 3rd-party modules
- `nosmt` — halves CPU performance
- `vsyscall=none` — may break older applications

---

## sysctl Settings Applied

Installed to `/etc/sysctl.d/90-secure-oss.conf`. Applied immediately and on every boot.

**Network:** TCP SYN cookies, disable ICMP echo/redirects/source routing, reverse path filtering, drop gratuitous ARP, log martian packets, IPv6 privacy extensions, disable RA.

**Kernel:** `yama.ptrace_scope=1`, `kptr_restrict=2`, `dmesg_restrict=1`, `sysrq=0`, unprivileged BPF disabled, BPF JIT hardening, `perf_event_paranoid=3`, kexec disabled, core dumps disabled, FIFO/regular/symlink/hardlink protection, improved ASLR entropy, `unprivileged_userfaultfd=0`, TTY ldisc autoload disabled.

---

## Module Blacklist Applied

Installed to `/etc/modprobe.d/secure-oss-blacklist.conf`.

- **Unused network protocols:** dccp, sctp, rds, tipc, n-hdlc, ax25, netrom, x25, rose, decnet, econet, af_802154, ipx, appletalk, psnap, p8023, p8022, can, atm
- **DMA attack vectors:** firewire-core, firewire-ohci, firewire-sbp2, firewire-net, ohci1394, sbp2, dv1394, raw1394, video1394
- **Unused filesystems:** cramfs, freevxfs, jffs2, hfs, hfsplus, udf, cifs, nfs, nfsv3, nfsv4, ksmbd, gfs2, reiserfs, jfs, 9p, ceph, afs, ecryptfs
- **Miscellaneous:** vivid (CVE-2020-10673)

**Not blacklisted** (unlike secureblue):
- `bluetooth` — desktop users need Bluetooth for peripherals
- `thunderbolt` — required for USB-C/DisplayPort on most modern laptops (note in config file)
- `xfs` — Fedora default filesystem (note in config file)

---

## Idempotency

Applied sections are tracked in `/etc/secure_oss/applied/`. Re-running the script
will skip already-applied sections. To re-apply a section:

```bash
sudo rm /etc/secure_oss/applied/dns
sudo bash harden.sh --skip kernel,sysctl,modules  # re-run only dns and remaining
```

All output is logged to `/var/log/secure_oss.log`.

---

## Differences from Silverblue Scripts

| Area | Silverblue | Fedora (this) |
|---|---|---|
| Base hardening | secureblue OCI image | Applied by our scripts |
| Kernel args | bootc kargs / ostree | grubby |
| sysctl | secureblue baked in | lib/sysctl-hardening.conf |
| Module blacklist | secureblue baked in | lib/modprobe-blacklist.conf |
| DNS stack | dnsconfd + unbound | systemd-resolved |
| Package manager | rpm-ostree / Flatpak | dnf |
| /usr writability | Read-only | Writable |
| DE-specific | Not applicable | GNOME + KDE auto-detected |
