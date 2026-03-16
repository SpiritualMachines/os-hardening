# Windows 11 — Provisioning & Hardening Instructions

## Overview

These scripts apply a privacy-respecting, anti-surveillance security baseline to Windows 11. The workflow is split into two stages:

1. **`provision.ps1`** — Removes pre-installed bloatware and sponsored content. Run once on a fresh installation.
2. **`harden.ps1`** — Applies all security hardening across 16 areas. Safe to re-run at any time (idempotent).

**Usability guarantee:** No hardening step breaks the Windows shell, standard application compatibility, or daily-use features (Bluetooth, printing, Microsoft Store, Windows Hello). Each step that touches a user-facing feature has a documented impact assessment in the script.

---

## Prerequisites

- Windows 11 Home / Pro / Enterprise (tested on 23H2, 24H2)
- PowerShell 5.1 (built-in) — no PowerShell 7 required
- Run as Administrator
- Internet access not required for hardening

---

## Scripts

### `provision.ps1` — Bloatware removal and winget verification

Run first on a fresh Windows 11 installation.

```powershell
# Run in PowerShell as Administrator

.\provision.ps1                              # Remove all bloatware
.\provision.ps1 -DryRun                      # Preview changes only
.\provision.ps1 -KeepXbox                    # Keep Xbox apps
.\provision.ps1 -KeepOneDrive               # Keep OneDrive installed
.\provision.ps1 -KeepTeams                   # Keep Microsoft Teams
```

**What it does:**

| Step | Details |
|---|---|
| Remove AppX packages | Removes pre-installed Microsoft apps: Cortana, Bing News/Weather/Finance/Sports, Xbox apps (optional), Skype, Microsoft Teams consumer (optional), Clipchamp, Solitaire Collection, MixedReality Portal, and other OEM-installed bundles. Uses `Remove-AppxPackage -AllUsers` and `Remove-AppxProvisionedPackage` to prevent re-installation. |
| Disable sponsored content | Disables File Explorer sync provider notifications (OneDrive banners), Start Menu suggested apps, and lock screen spotlight ads. |
| Verify winget | Confirms winget (Windows Package Manager) is available. winget is used for optional tool installation steps. |

> **OneDrive:** `provision.ps1 -KeepOneDrive` prevents removal of the OneDrive client. Note that `harden.ps1` separately disables OneDrive *cloud sync* via policy regardless of this flag, unless you also pass `-Skip @('onedrive')` to `harden.ps1`.

---

### `harden.ps1` — Security hardening

Run after `provision.ps1`. Applies all 16 hardening sections.

```powershell
# Run in PowerShell as Administrator

.\harden.ps1                                 # Apply all hardening
.\harden.ps1 -DryRun                         # Preview changes only
.\harden.ps1 -Skip @('bitlocker','monitor')  # Skip specific sections
```

**Parameters:**

| Parameter | Description |
|---|---|
| `-DryRun` | Show what would be done without making changes |
| `-Skip` | Array of section names to skip (see sections table) |
| `-KeepRDP` | Do not disable Remote Desktop (keep if you actively use RDP) |
| `-KeepWinRM` | Do not disable WinRM (keep if you manage this machine via PS remoting) |

---

## Sections Applied

| # | Section | `--skip` name | What it does |
|---|---|---|---|
| 1 | Telemetry | `telemetry` | Disables Windows telemetry at all levels via registry. Sets `AllowTelemetry=0`, disables DiagTrack service, disables Connected User Experiences and Telemetry. Disables Activity History, Feedback Hub, Diagnostic Data Viewer. |
| 2 | Privacy | `privacy` | Disables advertising ID, app access to location/camera/microphone/contacts/calendar by default, disables Windows Timeline, disables Cortana search suggestions. |
| 3 | MDM Enrollment Block | `mdm` | Prevents MDM/Intune enrollment via registry keys under `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM`. Null-routes known MDM enrollment endpoints in the hosts file (Intune, Jamf, Kandji, and others). |
| 4 | Remote Access | `remoteaccess` | Disables Remote Desktop (unless `-KeepRDP`), Remote Assistance, WinRM (unless `-KeepWinRM`), Remote Registry service, and Telnet client if installed. |
| 5 | Firewall | `firewall` | Enables Windows Firewall on all profiles (Domain/Private/Public). Sets default-deny inbound on Public profile. Removes any pre-existing inbound rules for Remote Desktop if RDP is disabled. |
| 6 | Network Protocols | `network` | Disables SMBv1 via `Set-SmbServerConfiguration`. Disables LLMNR via registry (`EnableMulticast=0`). Disables NetBIOS over TCP/IP on all adapters. |
| 7 | Services | `services` | Disables/stops: `RemoteRegistry`, `WerSvc` (Windows Error Reporting), `DiagTrack`, `dmwappushservice`, `MapsBroker`, `RetailDemo`, `SharedAccess`. |
| 8 | Telemetry Scheduled Tasks | `tasks` | Disables the scheduled tasks used by Windows for telemetry collection: Application Experience, Customer Experience Improvement Program (CEIP), Disk Diagnostics, ProgramDataUpdater, and others. |
| 9 | OneDrive | `onedrive` | Disables OneDrive cloud sync via Group Policy registry key (`DisableFileSyncNGSC=1`). Does not uninstall the client. |
| 10 | AutoPlay / AutoRun | `autoplay` | Disables AutoPlay for all media and devices. Disables AutoRun via registry (`NoDriveTypeAutoRun=255`). Prevents automatic execution of content from USB drives and optical media. |
| 11 | BitLocker | `bitlocker` | If TPM is available and drive is not already encrypted: enables BitLocker on the system drive with TPM+PIN protector. If TPM is absent, outputs manual encryption guidance. |
| 12 | Delivery Optimization | `deliveryopt` | Disables Windows Update Delivery Optimization peer-to-peer sharing. Prevents the machine from acting as an update relay for other devices (local network or internet). |
| 13 | UAC | `uac` | Sets UAC to always-notify mode (`ConsentPromptBehaviorAdmin=2`). Enables UAC for all administrators. Does not disable UAC. |
| 14 | Windows Defender | `defender` | Enables cloud-delivered protection, automatic sample submission, real-time protection, network protection (block mode), and PUA (potentially unwanted app) protection. Enables ASR (Attack Surface Reduction) rules for Office and script-based threats. |
| 15 | Intel ME/AMT | `amt` | Disables Intel LMS (Local Manageability Service), UNS, and IntelAMTAgent services. Adds Windows Firewall rules blocking TCP 16992–16995, 664 and UDP 623. Adds LMS/UNS/IntelAMTAgent to the RMM monitoring list. |
| 16 | MDM/RMM Monitoring | `monitor` | Deploys active monitoring for MDM enrollment and RMM agent installation (see Monitoring section below). |

---

## MDM/RMM Active Monitoring (`monitor` section)

Deploys a PowerShell monitor script and three scheduled tasks that provide real-time alerts when remote management activity is detected.

**Three tasks deployed:**

| Task | Trigger | Principal | Purpose |
|---|---|---|---|
| `SecureOSS-MDMMonitor-Logon` | User logon | `BUILTIN\Users` (interactive) | Shows toast notification for any pending alerts on login; scans running services and processes |
| `SecureOSS-MDMMonitor-NewService` | Event ID 7045 (Service Control Manager) | `SYSTEM` | Triggers immediately when any new service is installed |
| `SecureOSS-MDMMonitor-MDMEnroll` | DeviceManagement-Enterprise-Diagnostics-Provider events 20219, 1, 2 | `SYSTEM` | Triggers on MDM enrollment events |

**What is scanned:**
- 30+ known RMM service names (TeamViewer, AnyDesk, Datto RMM, Kaseya, Splashtop, BeyondTrust/Bomgar, NinjaOne, ConnectWise, ScreenConnect, GoTo Resolve, Zoho Assist, Atera, Syncro, RemotePC, LogMeIn, Intel LMS/UNS, and others)
- 14+ known RMM process names
- `RemoteRegistry` service status

> The detection lists cover common commercial tools but are not exhaustive — new agents and rebranded products appear regularly. Review and extend `$KnownRMMServices` and `$KnownRMMProcesses` in `C:\ProgramData\secure_oss\scripts\Invoke-MDMMonitor.ps1` to match tools relevant to your environment.

**Alert delivery:**
- **Toast notification** shown on the active desktop session (appears immediately if a user is logged in)
- **Alert files** written to `C:\ProgramData\secure_oss\alerts\` — displayed as toasts on next logon if no session is active at trigger time

**Event log:**
Alerts are also written to the Windows Application event log under source `SecureOSS`.

```powershell
# View alert history
Get-EventLog -LogName Application -Source SecureOSS
```

---

## Intel ME/AMT Hardening (`amt` section)

See the [Monitoring section above](#mdmrmm-active-monitoring-monitor-section) for LMS/UNS service disabling.

**Critical limitation:** AMT in shared-NIC mode intercepts packets at the NIC firmware level, before Windows Firewall processes them. Host-level firewall rules are **not effective** against AMT traffic.

**Recommended mitigation:** Block AMT ports on your **gateway/router**:
```
TCP: 16992, 16993, 16994, 16995, 664
UDP: 623
```

For full LAN-level protection, use **VLAN isolation** with inter-VLAN rules blocking the above ports.

---

## Registry Paths (Key Hardening Areas)

| Area | Registry path |
|---|---|
| Telemetry level | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry` |
| MDM enrollment block | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM\DisableRegistration` |
| LLMNR disable | `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast` |
| AutoRun disable | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun` |
| OneDrive sync disable | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC` |
| UAC always-notify | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` |
| Advertising ID | `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo\Enabled` |

All registry operations in `harden.ps1` include a comment with the full key path and the value being set.

---

## Idempotency

Applied sections are tracked as marker files in `C:\ProgramData\secure_oss\applied\`. Re-running skips already-applied sections.

To force re-application of a section:
```powershell
Remove-Item 'C:\ProgramData\secure_oss\applied\telemetry' -Force
.\harden.ps1 -Skip @('privacy','mdm','remoteaccess','firewall','network','services',
                      'tasks','onedrive','autoplay','bitlocker','deliveryopt',
                      'uac','defender','amt','monitor')
```

All output is written to `C:\ProgramData\secure_oss\secure_oss.log` and to the console.

---

## Full Workflow

```powershell
# Step 1 — remove bloatware (run in elevated PowerShell)
.\provision.ps1

# Step 2 — preview hardening
.\harden.ps1 -DryRun

# Step 3 — apply hardening
.\harden.ps1

# Step 4 — skip BitLocker if you manage encryption separately
.\harden.ps1 -Skip @('bitlocker')

# Step 5 — verify
Get-Service DiagTrack | Select-Object Status, StartType     # should be Disabled
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol  # should be False
(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection').AllowTelemetry
Get-ScheduledTask SecureOSS-MDMMonitor-Logon
```

---

## Post-Hardening Checklist

```
[ ] Reboot to apply service disables and scheduled task registration
[ ] Verify Windows Defender is active: Get-MpComputerStatus
[ ] Confirm BitLocker status: manage-bde -status C:
[ ] Test Start Menu and Microsoft Store still function
[ ] Confirm Bluetooth and printing still work (if used)
[ ] Review alert folder for any pre-existing detections:
      dir C:\ProgramData\secure_oss\alerts\
[ ] Block AMT ports on your gateway: TCP 16992-16995, 664 / UDP 623
```

---

## Library: `lib\Common.ps1`

Sourced by both scripts. Provides:
- `Write-Log`, `Write-Warn`, `Write-Error` — timestamped output to console and log file
- `Invoke-Section` — runs a hardening section with skip-list checking and error handling
- `Test-Applied` / `Mark-Applied` — idempotency marker management
- `Set-Registry` — idempotent registry key setter with dry-run support
- `Invoke-Cmd` — dry-run-aware command execution wrapper
