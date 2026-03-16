# secure-oss — OS Hardening & Provisioning Scripts

A collection of post-installation hardening scripts for common operating systems, built around a consistent threat model and set of principles. Designed for security-conscious users, homelabbers, and professionals who want a well-documented, repeatable baseline — not a black-box tool that silently makes hundreds of undocumented changes.

## Target Platforms

| Directory | Platform | Type |
|---|---|---|
| `fedora/` | Fedora Workstation / KDE Plasma | Desktop (mutable) |
| `fedora-silverblue/` | Fedora Silverblue | Desktop (immutable, full) |
| `fedora-silverblue-light/` | Fedora Silverblue | Desktop (immutable, no extra packages) |
| `ubuntu-server/` | Ubuntu Server LTS | Headless server |
| `freebsd-unraid/freebsd/` | FreeBSD | Server / NAS |
| `freebsd-unraid/unraid/` | Unraid | NAS / homelab storage |
| `windows11/` | Windows 11 | Desktop |

---

## Philosophy

**Auditability over automation.** Every change is documented with a comment explaining *why* it is applied. You should be able to read these scripts and understand exactly what they do before running them.

**Idempotent.** All scripts are safe to re-run. Re-running does not break existing configuration or apply settings twice.

**Dry-run first.** All scripts support `--dry-run` (Linux/BSD) or `-DryRun` (PowerShell) to preview changes before applying them.

**Usability is a hard constraint.** Hardening that prevents you from using the system normally is not hardening — it is sabotage. Desktop scripts target a CIS Level 1 equivalent posture; destructive Level 2 controls are not applied without explicit flags.

---

## Threat Model

These scripts defend against:

1. **MDM/RMM push** — IT departments, OEMs, or malicious actors enrolling or managing a device without consent via tools like Intune, Jamf, or commercial RMM agents.
2. **OS vendor telemetry** — Microsoft, Canonical, and others collecting usage data and call-home behavior.
3. **Network-level attackers** — Unauthorized access via open services, default credentials, or unfiltered ports.
4. **Physical access attackers** — Cold boot and evil maid attacks, mitigated by encryption configuration guidance.
5. **Malicious content at rest** — Relevant to NAS/storage use cases: accidental execution of malware stored on the array, service-triggered parsing of crafted files, path traversal via symlinks.

These scripts do **not** attempt to defend against nation-state adversaries or sophisticated targeted attacks.

---

## Hardening Coverage

### All Linux platforms

| Area | What is applied |
|---|---|
| Firewall | Default-deny inbound; outbound restrictions where practical |
| SSH | Key-only authentication, no root login, strong algorithm selection |
| Kernel parameters | Network stack hardening, anti-spoofing, kernel pointer hiding, BPF JIT hardening, unprivileged namespace restriction |
| Services | Unused and privacy-sensitive services disabled or masked |
| Telemetry blocking | OS and application call-home blocked via hosts file and service disabling |
| MDM enrollment | MDM enrollment endpoints null-routed; enrollment mechanisms disabled |
| Audit logging | auditd configured with security-relevant rules |
| Core dumps | Disabled to prevent credential/key leakage |

### Fedora (mutable) — additional

- SELinux enforcing mode verified and enforced
- GNOME and KDE privacy settings applied via gsettings / KDE config
- Flatpak sandbox policy review
- Optional: webcam disable, WireGuard kill-switch, bash environment lockdown

### Fedora Silverblue — additional

- Works within the immutable OS model — no changes that require a writable `/usr`
- Two variants: full (installs inotify-tools via rpm-ostree for real-time monitoring) and light (no extra packages, uses checksum-based polling)
- Flatpak sandboxing enforcement

### Ubuntu Server — additional

- UFW configured with default-deny
- fail2ban deployment
- Unattended-upgrades for security patches
- Ubuntu Advantage / Pro telemetry disabled
- cloud-init hardening

### Unraid

- iptables host firewall (default-deny inbound, DOCKER-USER chain for container port isolation)
- SSH hardening persisted to `/boot/config/ssh/`
- sysctl hardening persisted to `/boot/config/` and re-applied on every boot
- Optional: Unraid.net / cloud call-home blocking
- Optional: forensics share hardening (noexec bind mount, Samba symlink protection, Docker audit, media server exclusion markers)

See [`freebsd-unraid/unraid/INSTRUCTIONS.md`](freebsd-unraid/unraid/INSTRUCTIONS.md) for the full Unraid guide.

### Windows 11

- Telemetry disabled at all levels via registry and scheduled task removal
- MDM enrollment blocked via registry keys
- Activity History, Diagnostic Data, Error Reporting, Feedback Hub disabled
- Cortana disabled
- Remote Desktop, Remote Assistance, WinRM disabled (with flags to retain if needed)
- Windows Firewall configured; SMBv1 disabled; LLMNR and NetBIOS-over-TCP disabled
- AutoPlay / AutoRun disabled
- OneDrive consumer sync disabled
- BitLocker guidance included

See [`windows11/harden.ps1`](windows11/harden.ps1) inline documentation for the full list of registry paths and GPO settings applied.

---

## MDM/RMM Active Monitoring

The Fedora and Windows 11 scripts include an active monitoring component (applied as the `monitor` section) that provides real-time alerts when remote management activity is detected:

**What it monitors:**
- Installation or activation of known RMM agent services/processes (TeamViewer, AnyDesk, Datto RMM, Kaseya, Splashtop, BeyondTrust/Bomgar, NinjaOne, ConnectWise, ScreenConnect, GoTo Resolve, Zoho Assist, Atera, and others)
- Changes to critical system files: SSH config, sudoers, authorized_keys, cron jobs, systemd units
- MDM enrollment events (Windows: Event IDs in the DeviceManagement-Enterprise-Diagnostics-Provider log)
- New service installation (Windows: Event ID 7045)

**How alerts are delivered:**
- **Linux**: `logger` (systemd journal, `security.warning` facility) + `wall` broadcast to all TTYs + `notify-send` to all logged-in desktop sessions via D-Bus
- **Windows**: Toast notification on the active desktop session; alert files written to `C:\ProgramData\secure_oss\alerts\` for display on next logon if no session is active

The detection lists cover common commercial tools but are intentionally not exhaustive — new RMM agents and rebranded products appear regularly. Review and extend the lists for your specific environment.

---

## Intel ME / AMT Hardening

The `amt` section addresses Intel Management Engine (ME) and Active Management Technology (AMT) — firmware-level remote management that operates independently of the OS.

**What is applied:**
- `mei_me` and `mei_wdt` kernel modules blacklisted (severs the OS-to-ME communication channel)
- Intel LMS (Local Manageability Service) and related services disabled on Windows
- Firewall rules blocking AMT ports (TCP 16992–16995, 664 / UDP 623)
- AMT port listener detection included in the regular monitoring scan

**Important limitation:** AMT in shared-NIC mode intercepts packets at the NIC before the OS network stack processes them. Host-level firewall rules cannot fully stop AMT traffic. The most effective mitigation is blocking AMT ports **on your gateway/router** — an upstream device that is outside the NIC's control:

```
Ports to block on your gateway: TCP 16992, 16993, 16994, 16995, 664 / UDP 623
```

For full LAN-level isolation (same-subnet lateral movement), place affected machines on a dedicated VLAN with inter-VLAN forwarding rules that block AMT ports.

---

## Usage

### Linux / BSD

```bash
# Preview changes without applying
sudo bash harden.sh --dry-run

# Apply all hardening
sudo bash harden.sh

# Skip specific sections
sudo bash harden.sh --skip telemetry,monitor

# Platform-specific options (see each script's --help)
sudo bash harden.sh --help
```

### Windows 11

```powershell
# Run in PowerShell as Administrator

# Preview changes without applying
.\harden.ps1 -DryRun

# Apply all hardening
.\harden.ps1

# Skip specific sections
.\harden.ps1 -Skip @('telemetry','monitor')
```

---

## Optional Scripts

| Script | Platform | Purpose |
|---|---|---|
| `fedora/optional/disable-webcam.sh` | Fedora | Blacklist UVC kernel module to disable webcam |
| `fedora/optional/wireguard-killswitch.sh` | Fedora | WireGuard kill-switch firewall rules |
| `fedora/optional/bash-lockdown.sh` | Fedora | Restrict shell environment for shared/kiosk use |
| `fedora-silverblue/optional/*` | Silverblue | Same optional scripts adapted for immutable OS |
| `freebsd-unraid/unraid/optional/forensics-share.sh` | Unraid | Harden a share for storing malware samples or forensic artifacts |

---

## Requirements

| Platform | Requirements |
|---|---|
| Fedora (mutable) | Run as root; `dnf` available |
| Fedora Silverblue (full) | Run as root; internet access for `rpm-ostree` |
| Fedora Silverblue (light) | Run as root; no extra packages required |
| Ubuntu Server | Run as root; `apt` available |
| Unraid | Run as root on the Unraid host |
| Windows 11 | PowerShell 5.1+; run as Administrator |

---

## What These Scripts Do Not Cover

- Nation-state or targeted sophisticated attacks
- Application-layer vulnerabilities in installed software
- Supply chain attacks against package repositories
- Hardware implants
- Disk encryption setup (guidance is included but full-disk encryption must be configured at install time or via platform tools)

---

## License

MIT
