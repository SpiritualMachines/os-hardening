#!/usr/bin/env bash
# lib/gnome.sh — GNOME-specific hardening functions for Ubuntu Desktop
# Sourced by harden.sh when DE=gnome; not executed directly.
#
# Applies privacy and security settings specific to GNOME Shell and its
# associated services on Ubuntu. Settings are applied at both the system
# level (systemctl, dconf locks) and the user level (gsettings via sudo -u).
#
# Ubuntu Desktop ships GNOME as its sole supported desktop environment.
# Several Ubuntu-specific services (whoopsie, kerneloops, apport) are also
# masked here as a belt-and-suspenders measure after provision.sh removes them.

# ---------------------------------------------------------------------------
# GNOME system-level service hardening
# ---------------------------------------------------------------------------

gnome_harden_services() {
    log "Hardening GNOME system services"

    # gnome-remote-desktop provides RDP and VNC remote access to the desktop.
    # Masking prevents it from running even if re-enabled by a package update
    # or the user toggling "Remote Desktop" in GNOME Settings.
    if systemctl cat gnome-remote-desktop.service &>/dev/null; then
        log "Masking gnome-remote-desktop.service (RDP/VNC remote desktop access)"
        run_cmd systemctl mask gnome-remote-desktop.service
        run_cmd systemctl stop gnome-remote-desktop.service 2>/dev/null || true
    else
        log "gnome-remote-desktop.service not present — skipping"
    fi

    # GeoClue provides location services to GNOME and applications. Masking it
    # prevents any application from obtaining location data via the portal, even
    # if portal permissions have been granted. Most desktop users do not need
    # precise hardware-based location.
    if systemctl cat geoclue.service &>/dev/null; then
        log "Masking geoclue.service (location services)"
        run_cmd systemctl mask geoclue.service
    else
        log "geoclue.service not present — skipping"
    fi

    # Tracker miners index files for GNOME Search. They read file contents and
    # metadata, which increases the local attack surface and has historically
    # had bugs causing sensitive data leakage. We disable the miners but leave
    # the tracker daemon itself (required by GNOME Files / Nautilus).
    for tracker_unit in tracker-miner-fs-3.service tracker-miner-rss-3.service; do
        if systemctl cat "${tracker_unit}" &>/dev/null; then
            log "Masking ${tracker_unit} (file indexing miner)"
            run_cmd systemctl mask "${tracker_unit}"
        else
            log "${tracker_unit} not present — skipping"
        fi
    done

    # whoopsie is Ubuntu's crash submission service. It sends crash reports to
    # errors.ubuntu.com. provision.sh removes the package; we mask the service
    # here as a belt-and-suspenders measure in case the package remains or is
    # reinstalled (e.g. as a dependency of ubuntu-desktop).
    if systemctl cat whoopsie.service &>/dev/null; then
        log "Masking whoopsie.service (Ubuntu crash report submission)"
        run_cmd systemctl mask whoopsie.service
        run_cmd systemctl stop whoopsie.service 2>/dev/null || true
    else
        log "whoopsie.service not present — skipping"
    fi

    # kerneloops collects and submits kernel oops reports to kerneloops.org.
    # Like whoopsie, this is a call-home service removed by provision.sh.
    if systemctl cat kerneloops.service &>/dev/null; then
        log "Masking kerneloops.service (kernel oops submission)"
        run_cmd systemctl mask kerneloops.service
        run_cmd systemctl stop kerneloops.service 2>/dev/null || true
    else
        log "kerneloops.service not present — skipping"
    fi

    # apport is Ubuntu's crash handler / bug reporter. It intercepts crashes,
    # collects potentially sensitive process memory, and offers to submit to
    # Canonical. Removed by provision.sh; masked here defensively.
    if systemctl cat apport.service &>/dev/null; then
        log "Masking apport.service (Ubuntu crash handler)"
        run_cmd systemctl mask apport.service
        run_cmd systemctl stop apport.service 2>/dev/null || true
    else
        log "apport.service not present — skipping"
    fi
}

# ---------------------------------------------------------------------------
# GNOME user-level privacy settings
# Applied via gsettings for the calling (non-root) user.
# These settings are also backed by dconf locks (see gnome_apply_dconf_locks)
# to prevent them from being reverted via the GNOME Settings UI.
# ---------------------------------------------------------------------------

gnome_harden_user_settings() {
    local target_user
    target_user="$(get_sudo_user)" || {
        warn "Skipping user-level GNOME settings — could not determine user"
        return 0
    }

    log "Applying GNOME privacy settings for user: ${target_user}"

    # -- Privacy settings ----------------------------------------------------

    # Disable location services in GNOME Settings. This controls the global
    # location switch; individual app permissions are irrelevant if the switch
    # is off.
    run_as_user "${target_user}" gsettings set \
        org.gnome.system.location enabled false

    # Disable automatic problem reporting. On Ubuntu, this setting controls
    # whether GNOME offers to file bug reports via Launchpad/Apport.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy report-technical-problems false

    # Disable sending software usage statistics. This prevents GNOME from
    # transmitting app usage telemetry to GNOME project servers.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy send-software-usage-stats false

    # Stop retaining recent file history. GNOME Files and other apps use this
    # to populate "Recent" views. Disabling reduces local data exposure.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy remember-recent-files false

    # Clear recent files automatically after 1 day (86400 seconds effectively).
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy recent-files-max-age 1

    # Disable app usage history. GNOME Shell uses this to rank search results.
    # Disabling prevents building a profile of which applications are used
    # most frequently.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy remember-app-usage false

    # Disable GNOME connectivity check. GNOME's NetworkManager integration
    # periodically contacts connectivity-check.ubuntu.com to test internet
    # access. While functional, it sends the Ubuntu version and OS information
    # to Canonical. This gsettings key disables that check in GNOME's UI layer.
    # We also configure NetworkManager itself in the telemetry section.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy connectivity-check-enabled false 2>/dev/null || true

    # -- Remote desktop (user level) -----------------------------------------

    # Disable RDP in GNOME Remote Desktop user settings. This is belt-and-
    # suspenders: the service is masked at the system level, but we also
    # disable the user-level toggle in case the service unit is ever unmasked.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.remote-desktop.rdp enable false 2>/dev/null || true

    # -- Screen lock ---------------------------------------------------------

    # Lock the screen when the display turns off, not just on explicit idle.
    # Ensures the screen is always locked when physically unattended.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.screensaver lock-enabled true

    # Lock screen after 5 minutes of idle (screensaver activation). This delay
    # between activation and actual lock allows a brief grace period to return
    # without re-entering credentials.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.screensaver lock-delay 300

    # Blank the screen after 5 minutes of idle. Short idle timeout reduces the
    # window for shoulder-surfing when the user steps away.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.session idle-delay 300

    # -- Notifications on lock screen ----------------------------------------

    # Hide notification content on the lock screen. Without this, message
    # previews from email, messaging apps, and other notifications are visible
    # to anyone who can see the locked screen.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.notifications show-in-lock-screen false

    log "GNOME user settings applied for ${target_user}"
}

# ---------------------------------------------------------------------------
# GNOME dconf system locks
# Locks prevent users from overriding security-sensitive settings via
# the GNOME Settings UI or gsettings CLI. Applied system-wide.
# dconf update must be run after modifying these files.
# ---------------------------------------------------------------------------

gnome_apply_dconf_locks() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would write dconf lock files to /etc/dconf/db/local.d/locks/"
        return 0
    fi

    log "Applying dconf system policy locks"

    mkdir --parents /etc/dconf/db/local.d /etc/dconf/db/local.d/locks

    # System-level defaults written to the dconf 'local' database.
    # These values are applied as system defaults; the locks file below
    # prevents users from overriding the security-critical subset.
    write_file "/etc/dconf/db/local.d/00-secure-oss-privacy" \
"[org/gnome/system/location]
enabled=false

[org/gnome/desktop/privacy]
report-technical-problems=false
send-software-usage-stats=false
remember-recent-files=false
connectivity-check-enabled=false

[org/gnome/desktop/remote-desktop/rdp]
enable=false"

    # Lock the location and remote desktop settings so they cannot be changed
    # from the GNOME Settings UI or via gsettings by a user.
    # Comment out any lock you do not want to enforce (e.g. if users need
    # location services for a specific application).
    write_file "/etc/dconf/db/local.d/locks/secure-oss-locks" \
"/org/gnome/system/location/enabled
/org/gnome/desktop/remote-desktop/rdp/enable
/org/gnome/desktop/privacy/report-technical-problems
/org/gnome/desktop/privacy/send-software-usage-stats"

    # Recompile the dconf database. Without this, the files above have no effect.
    run_cmd dconf update
}

# ---------------------------------------------------------------------------
# Main entry point — called by harden.sh
# ---------------------------------------------------------------------------

harden_gnome() {
    gnome_harden_services
    gnome_harden_user_settings
    gnome_apply_dconf_locks
}
