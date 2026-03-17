# macOS — Provisioning & Hardening Instructions

## Overview

These scripts apply a practical security baseline to macOS 13 (Ventura), 14 (Sonoma), or 15 (Sequoia). The workflow is split into two stages:

1. **`provision.sh`** — Checks prerequisites and reports security posture. Run once on a fresh installation or before first hardening.
2. **`harden.sh`** — Applies all hardening. Safe to re-run at any time (idempotent).

---

## Prerequisites

- macOS 13 (Ventura), 14 (Sonoma), or 15 (Sequoia)
- Admin user account with sudo access
- SIP must remain **enabled** — these scripts are designed to work within SIP constraints and do not attempt to disable it
- Xcode Command Line Tools — `provision.sh` will check and prompt to install if missing (provides Python 3 required by `harden.sh`)

---

## Scripts

### `provision.sh` — Preflight checks and prerequisites

Run first. Checks the security posture of your system and prepares it for `harden.sh`. Unlike the Linux scripts, this does not install packages — macOS does not have a system package manager to provision.

```
Usage: sudo bash provision.sh [OPTIONS]

Options:
  --dry-run   Show what would be done without making changes
  --help      Show this help
```

**What it checks:**

| Step | What it does |
|---|---|
| macOS version check | Verifies macOS 13 or later; logs the full version and build number |
| SIP status check | Runs `csrutil status` and logs the result; warns if SIP is disabled. SIP can only be re-enabled from Recovery Mode — the script does not attempt this. |
| FileVault check | Runs `fdesetup status` and logs result. If FileVault is off, prints step-by-step instructions to enable it. The script cannot enable FileVault silently (a recovery key must be saved interactively). |
| Gatekeeper check/enable | Runs `spctl --status`. If disabled: on macOS 13–14, re-enables it with `spctl --master-enable`; on macOS 15 (Sequoia), warns and directs to System Settings (Apple removed CLI Gatekeeper management in Sequoia). |
| Xcode CLI Tools check | Checks `xcode-select -p`. If missing, triggers the GUI installer with `xcode-select --install` and exits with instructions to re-run `provision.sh` after installation completes. |
| Marker directory creation | Creates `/etc/secure_oss/applied/` for idempotency tracking |

A summary table is printed at the end showing the status of each check.

---

### `harden.sh` — System hardening

Run after `provision.sh`. Applies all security controls.

```
Usage: sudo bash harden.sh [OPTIONS]

Options:
  --skip SECTIONS   Comma-separated list of sections to skip
  --dry-run         Show what would be done without making changes
  --help            Show this help
```

**Sections applied:**

| # | Section | What it does |
|---|---|---|
| 1 | `firewall` | Enables Application Firewall (`socketfilterfw`); sets block-all incoming connections; enables stealth mode (no ICMP ping response, no closed-port RST); enables logging to `/var/log/appfirewall.log` |
| 2 | `pf` | Installs a pf anchor file at `/etc/pf.anchors/secure_oss` blocking Intel AMT/ME and IPMI ports (TCP 16992–16995, 664; UDP 623); loads via a `com.secure_oss.pf` LaunchDaemon that persists across reboots |
| 3 | `remote` | Disables SSH (Remote Login) via `launchctl disable system/com.openssh.sshd`; disables Screen Sharing; deactivates Remote Management (ARD) via `kickstart -deactivate`; disables Remote Apple Events |
| 4 | `siri` | Disables Siri via `defaults write /Library/Preferences/com.apple.assistant.support 'Assistant Enabled' false`; removes Siri from menu bar; disables voice trigger; opts out of Siri improvement programs; stops Siri model update daemon |
| 5 | `telemetry` | Sets `CrashReporter DialogType none`; sets `DiagnosticMessagesHistory.plist` `AutoSubmit=false` and `ThirdPartyDataSubmit=false`; disables `ReportCrash`, `SubmitDiagInfo`, and `DiagnosticReportSyncCopier` via launchctl; blocks Apple analytics and third-party telemetry domains in `/etc/hosts`; flushes DNS cache |
| 6 | `mdm` | Blocks Apple DEP/ADE enrollment endpoints (`deviceenrollment.apple.com`, `mdmenrollment.apple.com`, `iprofiles.apple.com`) and third-party MDM vendor domains in `/etc/hosts`; flushes DNS cache |
| 7 | `spotlight` | Disables Spotlight Suggestions and Siri natural language search categories via `defaults write com.apple.Spotlight orderedItems`; disables Safari universal search and search suggestions; disables Look Up web queries; restarts Spotlight to apply |
| 8 | `airdrop` | Restricts AirDrop to Contacts Only via `defaults write com.apple.sharingd DiscoverableMode "Contacts Only"`; restarts `sharingd` to apply immediately |

---

## What These Scripts Cannot Automate

Some macOS security controls require user interaction or hardware-level operations that cannot be performed by a shell script:

| Control | Why it cannot be automated | How to apply manually |
|---|---|---|
| **FileVault enable** | Requires interactive recovery key generation and user confirmation | `sudo fdesetup enable` (interactive) or System Settings > Privacy & Security > FileVault |
| **SIP management** | Requires booting into macOS Recovery Mode; cannot be changed from a running OS | Restart holding Command+R (Intel) or power button (Apple Silicon) > Terminal > `csrutil enable` |
| **Supervised device MDM removal** | Hardware-level enrollment tied to device serial number in Apple Business Manager; hosts-file blocking cannot stop this | Device must be released from Apple Business Manager by the organization that enrolled it |
| **Gatekeeper on macOS 15 Sequoia** | Apple removed `spctl --master-enable` in Sequoia | System Settings > Privacy & Security > Security > set to "App Store and identified developers" |

---

## Verification Commands

Run these after `harden.sh` to confirm each control was applied:

```bash
# Application Firewall
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall

# pf anchor (AMT port blocking)
sudo pfctl -a secure_oss -sr

# Remote access services (all three should show "disabled")
sudo launchctl print-disabled system | grep -E 'sshd|screensharing|AEServer'

# FileVault
fdesetup status

# Gatekeeper
spctl --status

# SIP
csrutil status

# Siri (should be "0" / false)
defaults read com.apple.Siri StatusMenuVisible
defaults read com.apple.Siri VoiceTriggerUserEnabled

# AirDrop (should be "Contacts Only")
defaults read com.apple.sharingd DiscoverableMode

# Hosts-file blocks applied
grep "secure_oss" /etc/hosts | head -5
```

---

## Post-Hardening Checklist

```
[ ] Verify FileVault is enabled: fdesetup status
[ ] Verify SIP is enabled: csrutil status  (should show "enabled")
[ ] Verify Application Firewall on: System Settings > Network > Firewall — On
[ ] Verify Remote Login is off: System Settings > General > Sharing — Remote Login off
[ ] Verify Remote Management is off: System Settings > General > Sharing — Remote Management off
[ ] Verify Screen Sharing is off: System Settings > General > Sharing — Screen Sharing off
[ ] Verify AirDrop: Finder > AirDrop — set to "Contacts Only" (or confirm in Finder sidebar)
[ ] Verify Siri is off: System Settings > Siri & Spotlight — Ask Siri off
[ ] Reboot to ensure all launchctl disable changes take full effect
```

---

## Idempotency

Applied sections are tracked in `/etc/secure_oss/applied/`. Re-running `harden.sh` is safe — sections that have already been applied will run again (all sections are idempotent by design; hosts-file blocks use named markers that replace themselves on re-run).

To re-apply a single section without running the others, use `--skip`:

```bash
# Re-apply only the telemetry section
sudo bash harden.sh --skip firewall,pf,remote,siri,mdm,spotlight,airdrop

# Re-apply only MDM blocking
sudo bash harden.sh --skip firewall,pf,remote,siri,telemetry,spotlight,airdrop
```

All output is logged to `/var/log/secure_oss.log`.

---

## Full Workflow

```bash
# Step 1 — preflight checks
sudo bash provision.sh

# Step 2 — apply hardening
sudo bash harden.sh

# Step 2a — dry run first to preview changes
sudo bash harden.sh --dry-run

# Step 2b — skip sections you don't want
sudo bash harden.sh --skip siri,spotlight

# Step 3 — verify
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
fdesetup status
csrutil status
sudo launchctl print-disabled system | grep -E 'sshd|screensharing|AEServer'
```

---

## Library: `lib/common.sh`

Sourced by all scripts. Provides shared logging, dry-run support, idempotency markers, DNS cache flushing, and argument parsing. Adapted for macOS — does not use `restorecon`, `apt-get`, `dnf`, or any Linux-specific commands.
