# Kiosk Mode — Reference Notes

Design notes for future kiosk mode scripts across the mutable desktop platforms
in this project (Fedora, Ubuntu Desktop, Windows 11, macOS).

---

## How Kiosk Mode Works (per OS)

### Fedora / Ubuntu Desktop (GNOME)

**Session lock-down:**

- **`gnome-kiosk`** package (GNOME 42+) provides a purpose-built kiosk session
  type. GDM autologins a restricted user into a `gnome-kiosk` session that runs
  exactly one application fullscreen with no shell, no taskbar, no Alt+F4.
- Alternative: **`cage`** — a minimal Wayland compositor that runs a single app
  and exits when it closes. More lightweight than gnome-kiosk, no GNOME
  dependency.
- AppArmor/SELinux profiles restrict what the kiosk user can exec.

**Session-reset (wipe on logout):**

| Approach | How it works | Trade-off |
|---|---|---|
| **tmpfs home** | Mount `/home/kiosk` as `tmpfs` in fstab; RAM-only, vanishes on reboot/logout | Fastest; no disk writes; requires reboot to reset mid-session |
| **overlayfs** | Read-only "golden" lower layer + writable upper layer mounted at login; upper layer deleted on logout via PAM/systemd | Resets without reboot; more complex setup |
| **skeleton reset** | PAM `pam_exec` or systemd user service runs a script on session close that `rm -rf`s the home and re-copies from `/etc/kiosk-skel/` | Simplest to understand; brief delay on logout |

Allowed apps/files are stored outside the kiosk home (e.g. `/opt/kiosk/`) and
the kiosk user has no execute permission on anything else. The skel directory
seeds only what they should see.

---

### Windows 11

**Two built-in mechanisms:**

| Mode | Availability | What it does |
|---|---|---|
| **Assigned Access (single-app)** | Pro, Enterprise, Education | Locks a local account to one UWP or Win32 app. Explorer is replaced by a shell launcher. User can't reach the desktop, taskbar, or Start Menu. |
| **Multi-app Assigned Access** | Enterprise, Education only | XML config whitelists specific apps; everything else is blocked at the shell level. Taskbar is locked to only whitelisted apps. |

Configured via: `Settings > Accounts > Other users > Set up a kiosk`, or via
an XML provisioning package (`.ppkg`), or Group Policy / Intune.

**Session-reset:**

- **Logoff script** (GPO) that runs `rd /s /q %USERPROFILE%` and re-seeds from
  a template directory.
- **Unified Write Filter (UWF)** — Enterprise/IoT feature. Redirects all disk
  writes to a RAM overlay; on reboot everything is discarded. The Windows
  equivalent of overlayfs. This is what kiosk hardware (ATMs, POS terminals)
  actually uses.
- **Roaming profile delete on logoff** (GPO): `Computer Config > Admin
  Templates > System > User Profiles > Delete cached copies of roaming profiles`.

---

### macOS

macOS has no built-in single-app kiosk for unmanaged (non-MDM) devices. Options:

| Approach | Requires | What it does |
|---|---|---|
| **Guided Access** | Manual activation | Locks to current app, disables hardware buttons. Designed for temporary/accessibility use, not persistent kiosk. |
| **Single App Mode (SAM)** | MDM (Jamf, Intune) | MDM-enforced; always keeps one app in the foreground. Supervised devices only. |
| **Screen Time restrictions** | Local admin | Restrict which apps a user account can open. Does not prevent Finder/desktop access. |
| **Launchd watchdog** | Scripts | A LaunchAgent autostarts the kiosk app; a companion watchdog relaunches it if it exits. Combined with Finder/Dock restrictions via `defaults write`. |
| **Session cleanup LaunchDaemon** | Scripts | A LaunchDaemon triggered on session end deletes the kiosk user's home and re-copies from a template. (Apple deprecated `LogoutHook` in Ventura — LaunchDaemon is the modern replacement.) |

The most robust unmanaged approach on modern macOS: restricted local account +
Finder/Dock locked via `defaults write` + launchd watchdog + session-cleanup
LaunchDaemon.

---

## The "Wipe Everything Except X" Pattern

Common architecture across all platforms:

```
Boot / Login
   ├── Seed clean state  (copy skel / mount tmpfs or overlay)
   └── Launch kiosk app  (autologin + restricted session)

User Session
   ├── App runs; writes go to volatile scratch space
   └── Persistent allowed data lives on a separate, protected path

Logout / Reboot
   ├── Discard scratch space  (delete overlay / tmpfs vanishes)
   └── Return to login screen for next user
```

**"Certain apps"** = installed system-wide in a protected path the kiosk user
can read/exec but not modify.

**"Certain files"** = stored outside the kiosk home, symlinked or copied in at
session start from a read-only source of truth.

---

## Planned Script Locations

| Platform | Script | Status |
|---|---|---|
| Fedora | `fedora/optional/kiosk-setup.sh` | Not yet written |
| Ubuntu Desktop | `ubuntu-desktop/optional/kiosk-setup.sh` | Not yet written |
| Windows 11 | `windows11/kiosk.ps1` | Not yet written |
| macOS | `macos/optional/kiosk-setup.sh` | Not yet written |

### Scope for each planned script

**Linux (Fedora + Ubuntu Desktop):**
- Create a dedicated `kiosk` system user with no login shell
- Install `cage` or `gnome-kiosk` session
- Configure GDM/LightDM autologin for the kiosk user
- Choose reset mechanism (flag: `--reset tmpfs|overlay|skel`)
- Populate `/etc/kiosk-skel/` from a user-supplied template directory
- AppArmor profile to restrict the kiosk user to whitelisted executables

**Windows 11 (`kiosk.ps1`):**
- Create a local kiosk account
- Configure Assigned Access via the `AssignedAccess` CSP / XML
- Set up logoff cleanup script via GPO or scheduled task
- Optional: enable UWF if running on Enterprise

**macOS (`kiosk-setup.sh`):**
- Create a restricted local account
- Write `defaults write` Finder/Dock lockdown settings
- Install launchd watchdog LaunchAgent for the kiosk app
- Install session-cleanup LaunchDaemon
- Note: full Single App Mode requires MDM — document manual workaround
