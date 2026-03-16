# Fedora Silverblue — Provisioning & Hardening Instructions

## Overview

These scripts harden a Fedora Silverblue installation by first rebasing to the
**secureblue** OCI image (which handles deep kernel and system-level hardening),
then layering additional privacy and anti-MDM controls on top that secureblue
does not cover out of the box.

---

## What is secureblue?

**secureblue** is a hardened OCI image built on top of Fedora Atomic (Silverblue/Kinoite)
via the Universal Blue project. It is the foundation this workflow builds on.

### What secureblue already covers (we do not redo this)

| Area | Details |
|---|---|
| Kernel hardening | Comprehensive kargs: PTI, Spectre/Meltdown mitigations, IOMMU enforcement, kernel lockdown=confidentiality, ASLR improvements, entropy hardening |
| sysctl hardening | Network stack hardening, kernel pointer restrictions, ptrace block, BPF JIT hardening, io_uring disabled, core dumps disabled |
| Module blacklisting | Unused network protocols, exotic filesystems, FireWire/Thunderbolt (DMA attack prevention), Bluetooth toggle, vivid, GNSS |
| hardened_malloc | System-wide via /etc/ld.so.preload and systemd environment — applies to all processes |
| SUID/SGID removal | All SUID bits removed from /usr; sudo/su/pkexec deleted; run0 (polkit) used instead |
| SSH | sshd.service and all related sockets masked and disabled |
| Services disabled | Avahi/mDNS, GeoClue, CUPS, ModemManager, NFS daemons, SSSD |
| Firewall | Default-deny inbound; all ports and services removed from default zone |
| SELinux | Enforcing with custom policies for browser, Flatpak, file managers, user namespaces |
| DNS | systemd-resolved replaced by dnsconfd + unbound (encrypted DNS opt-in via ujust) |
| NTP | chrony with NTS-authenticated servers (GrapheneOS-sourced config) |
| Authentication | faillock (50 attempts, 24h lockout), pwquality (min 15 chars, all character classes) |
| Flatpak | Verified-only Flathub subset; sandboxing lockdown available via ujust |
| Auto-updates | Automatic staged OS, firmware, and container updates enabled |
| Supply chain | Image signing with cosign; SLSA provenance verification for bundled browser |
| Browser | Firefox removed; Trivalent (hardened Chromium fork) installed with provenance check |

### Gaps secureblue does NOT cover (our scripts fill these)

| Gap | Our solution |
|---|---|
| MDM/RMM domain blocking | `/etc/hosts` null-routing of ~50 known MDM endpoints |
| Telemetry domain blocking | `/etc/hosts` null-routing of crash reporters, analytics SDKs |
| Encrypted DNS not enforced | `harden.sh` configures Quad9/Mullvad DoT non-interactively |
| DHCP hostname leakage | NetworkManager config to suppress hostname in DHCP requests |
| MAC randomization (per-connection) | Upgrade from secureblue's per-network to per-connection randomization |
| USBGuard not enabled | Auto-generate policy and enable service on first run |
| Cockpit (web admin console) | Mask cockpit.socket |
| ABRT crash reporter | Mask all ABRT systemd units |

---

## Prerequisites

- Fedora Silverblue installed (Fedora 40 or newer recommended)
- Internet access
- `sudo` / root access
- A USB keyboard/mouse physically connected (required for USBGuard setup)

---

## Scripts

### `provision.sh` — Rebase to secureblue

Detects the current OCI deployment and rebases to the appropriate secureblue image.
Exits after staging the rebase — **a reboot is required** before running `harden.sh`.

```
Usage: sudo bash provision.sh [OPTIONS]

Options:
  --image IMAGE   secureblue image variant (default: silverblue-main)
                  silverblue-main          GNOME desktop
                  silverblue-nvidia-main   GNOME desktop + NVIDIA drivers
                  kinoite-main             KDE Plasma desktop
                  kinoite-nvidia-main      KDE Plasma + NVIDIA drivers
  --dry-run       Show what would be done without making changes
  --help          Show this help
```

**What it does:**
1. Verifies running on Fedora Silverblue
2. Detects whether already on secureblue (exits safely if so)
3. Detects NVIDIA GPU and warns if a non-NVIDIA image is selected
4. Rebases using `bootc switch` (preferred) or `rpm-ostree rebase` (fallback)
5. Sets a reboot sentinel to gate `harden.sh` until after reboot
6. Prints a prominent reboot notice

---

### `harden.sh` — Privacy and anti-MDM hardening

Applies all additional hardening on top of secureblue. Requires the system to
already be running the secureblue image (i.e., after `provision.sh` + reboot).

All sections are idempotent — safe to re-run at any time.

```
Usage: sudo bash harden.sh [OPTIONS]

Options:
  --dns PROVIDER    DNS-over-TLS provider: quad9 | mullvad | both (default: quad9)
  --skip SECTIONS   Comma-separated list of sections to skip
                    Values: dns, dhcp, mac, usbguard, mdm, telemetry, cockpit, abrt
  --dry-run         Show what would be done without making changes
  --help            Show this help
```

**Sections applied:**

| # | Section | What it does |
|---|---|---|
| 1 | `dns` | Configures Quad9 or Mullvad DNS-over-TLS via dnsconfd (secureblue's native DNS stack). Verifies resolution after applying. |
| 2 | `dhcp` | Writes NetworkManager config to suppress hostname in DHCPv4/v6 requests, preventing LAN hostname leakage. |
| 3 | `mac` | Upgrades MAC randomization from secureblue's per-network default to per-connection (new MAC on every connect). |
| 4 | `usbguard` | Generates USBGuard policy from currently connected USB devices, enables and starts the service. Safety-checks for HID devices before enabling. |
| 5 | `mdm` | Null-routes ~50 MDM/RMM domains in `/etc/hosts` (Jamf, Intune, Kandji, Fleet, Workspace ONE, MobileIron, Mosyle, Addigy, etc.) |
| 6 | `telemetry` | Null-routes known telemetry and crash reporting endpoints in `/etc/hosts` (Sentry, Amplitude, Segment, Mozilla, etc.) |
| 7 | `cockpit` | Masks `cockpit.socket` — the web-based admin console that exposes a local HTTP server. |
| 8 | `abrt` | Masks all ABRT (Automatic Bug Reporting Tool) systemd units that send crash data to Red Hat. |

---

### `optional/disable-webcam.sh` — Disable USB webcam

Blacklists the `uvcvideo` kernel module, preventing all UVC webcams from functioning.

> **Warning:** Breaks all video conferencing camera access. Only use if you have
> no need for a webcam.

```
Usage: sudo bash optional/disable-webcam.sh [--dry-run]
       sudo bash optional/disable-webcam.sh --enable   (re-enable)
```

---

### `optional/bash-lockdown.sh` — Shell config immutability

Uses `chattr +i` to make shell initialization files immutable, preventing
LD_PRELOAD injection via `~/.bashrc`, `~/.profile`, etc.

> **Warning:** Breaks installer tools that modify shell config (rustup, nvm,
> conda, pyenv). Only use if you manage shell config manually.

```
Usage: sudo bash optional/bash-lockdown.sh [--user USERNAME] [--dry-run]
       sudo bash optional/bash-lockdown.sh --unlock [--user USERNAME]
```

---

### `optional/wireguard-killswitch.sh` — WireGuard kill-switch template

Generates a WireGuard config with PreUp/PostDown rules that block ALL non-VPN
traffic while the tunnel is active. Prevents traffic leaks if the VPN drops.

```
Usage: sudo bash optional/wireguard-killswitch.sh [--interface wg0] [--dry-run]
       sudo bash optional/wireguard-killswitch.sh --remove --interface wg0
```

After running, edit `/etc/wireguard/wg0.conf` and fill in your provider's
server public key and endpoint IP, then:

```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

---

## Full Workflow

```bash
# Step 1 — Run on a fresh Fedora Silverblue install
sudo bash provision.sh

# Step 1a — If you have an NVIDIA GPU:
sudo bash provision.sh --image silverblue-nvidia-main

# Step 1b — If you want KDE Plasma instead of GNOME:
sudo bash provision.sh --image kinoite-main

# Step 2 — Reboot into secureblue
systemctl reboot

# Step 3 — Apply additional hardening (after reboot)
sudo bash harden.sh

# Step 3a — Use Mullvad DNS instead of Quad9:
sudo bash harden.sh --dns mullvad

# Step 3b — Skip USBGuard if no USB input devices are connected:
sudo bash harden.sh --skip usbguard

# Step 4 — Preview changes without applying (dry-run):
sudo bash harden.sh --dry-run

# Optional extras
sudo bash optional/disable-webcam.sh
sudo bash optional/bash-lockdown.sh
sudo bash optional/wireguard-killswitch.sh
```

---

## Shared Library: `lib/common.sh`

Sourced by all scripts — not executed directly. Provides:

| Function | Purpose |
|---|---|
| `require_root` | Exits if not running as root |
| `require_secureblue` | Exits if not on a secureblue deployment |
| `require_silverblue` | Exits if not on a Fedora Atomic variant |
| `run_cmd CMD` | Executes CMD; in dry-run mode, prints what would run |
| `write_file PATH CONTENT` | Writes file; dry-run safe; calls restorecon |
| `append_block PATH BEGIN END CONTENT` | Idempotent block writer for /etc/hosts style files |
| `log / warn / die` | Timestamped output to stdout and /var/log/secure_oss.log |
| `banner / reboot_notice` | Formatted ASCII box messages |
| `is_applied STEP` | Returns true if step marker exists in /etc/secure_oss/applied/ |
| `mark_applied STEP` | Writes step marker to prevent re-application |
| `set_reboot_pending` | Creates sentinel at /etc/secure_oss/pending-reboot |
| `check_reboot_pending` | Aborts with reboot notice if sentinel exists |
| `warn_if_ssh_will_disconnect` | Warns + 5s pause before operations that restart NetworkManager |

---

## Block Lists

### `lib/hosts-mdm.txt`

Domains null-routed to `0.0.0.0` to block MDM/RMM enrollment and management:

| Vendor | Domains covered |
|---|---|
| Jamf Pro / Jamf Now | jamf.com, jamfcloud.com, jamf.net |
| Microsoft Intune | manage.microsoft.com, enterpriseregistration.windows.net, dm.microsoft.com |
| Kandji | kandji.io and subdomains |
| Fleet | fleetdm.com and subdomains |
| VMware Workspace ONE | awmdm.com, air-watch.com, workspaceone.com |
| Ivanti / MobileIron | mobileiron.com, ivanti.com |
| Mosyle | mosyle.com and subdomains |
| Addigy | addigy.com and subdomains |
| SimpleMDM | simplemdm.com and subdomains |
| Cisco Meraki SM | meraki.com MDM endpoints |
| ManageEngine | manageengine.com MDM endpoints |
| Absolute / Computrace | absolute.com, absoluteapps.com, namequery.com |
| Puppet | puppet.com |
| Chef Infra | chef.io |
| SaltStack | saltproject.io |
| Miradore | miradore.com |
| SOTI MobiControl | soti.net |
| Hexnode | hexnode.com |
| IBM MaaS360 | maas360.com |

### `lib/hosts-telemetry.txt`

Domains null-routed to block crash reporting and analytics. Includes caveat
comments where domains overlap with update infrastructure.

Categories: Mozilla, Chromium, Sentry, Datadog, Amplitude, Segment, Mixpanel,
Heap, Fullstory, Hotjar, New Relic, Elastic APM, Red Hat, GNOME, Flathub.

---

## Idempotency and State

Applied sections are tracked via marker files in `/etc/secure_oss/applied/`.

```
/etc/secure_oss/
├── applied/
│   ├── dns           (timestamp of when DNS was configured)
│   ├── dhcp
│   ├── mac
│   ├── usbguard
│   ├── mdm
│   ├── telemetry
│   ├── cockpit
│   └── abrt
└── pending-reboot    (exists if provision.sh staged a rebase, removed by harden.sh)
```

To force re-application of a section, delete its marker:
```bash
sudo rm /etc/secure_oss/applied/dns
sudo bash harden.sh --skip dhcp,mac,usbguard,mdm,telemetry,cockpit,abrt
```

---

## Logs

All script output is written to `/var/log/secure_oss.log` in addition to stdout.

---

## Silverblue-Specific Notes

- `/usr` is **read-only** (ostree managed) — all configs go to `/etc` or `/var`
- `rpm-ostree install` stages changes; a reboot is required to apply them
- `/etc/resolv.conf` is owned by `dnsconfd` — never write to it directly
- `systemctl mask` is used instead of `rpm-ostree remove` where possible to avoid requiring reboots
- `restorecon` is called after every file write to maintain correct SELinux contexts
- `bootc switch` is preferred over `rpm-ostree rebase` on Fedora 40+
