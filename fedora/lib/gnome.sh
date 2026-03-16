#!/usr/bin/env bash
# lib/gnome.sh — GNOME-specific hardening functions
# Sourced by harden.sh when DE=gnome; not executed directly.
#
# Applies privacy and security settings specific to GNOME Shell and its
# associated services. Settings are applied at both the system level
# (systemctl, dconf locks) and the user level (gsettings via sudo -u).

# ---------------------------------------------------------------------------
# GNOME system-level service hardening
# ---------------------------------------------------------------------------

gnome_harden_services() {
    log "Hardening GNOME system services"

    # gnome-remote-desktop provides RDP and VNC remote access.
    # Masking the service prevents it from running even if enabled by a user
    # or re-enabled by a package update.
    if systemctl cat gnome-remote-desktop.service &>/dev/null; then
        log "Masking gnome-remote-desktop.service (RDP/VNC remote access)"
        run_cmd systemctl mask gnome-remote-desktop.service
        run_cmd systemctl stop gnome-remote-desktop.service 2>/dev/null || true
    else
        log "gnome-remote-desktop.service not present — skipping"
    fi

    # GeoClue provides location services. Masking it prevents any application
    # from obtaining location data, even if granted portal permission.
    if systemctl cat geoclue.service &>/dev/null; then
        log "Masking geoclue.service (location services)"
        run_cmd systemctl mask geoclue.service
    else
        log "geoclue.service not present — skipping"
    fi

    # Tracker miners index files for GNOME Search. While useful, they read
    # all files and their metadata. Disable if search is not needed.
    # We disable the miners but leave the tracker daemon (needed by Files app).
    for tracker_unit in tracker-miner-fs-3.service tracker-miner-rss-3.service; do
        if systemctl cat "${tracker_unit}" &>/dev/null; then
            log "Masking ${tracker_unit}"
            run_cmd systemctl mask "${tracker_unit}"
        fi
    done
}

# ---------------------------------------------------------------------------
# GNOME user-level privacy settings
# Applied via gsettings for the calling (non-root) user.
# ---------------------------------------------------------------------------

gnome_harden_user_settings() {
    local target_user
    target_user="$(get_sudo_user)" || {
        warn "Skipping user-level GNOME settings — could not determine user"
        return 0
    }

    log "Applying GNOME privacy settings for user: ${target_user}"

    # -- Privacy settings ----------------------------------------------------

    # Disable location services in GNOME settings
    run_as_user "${target_user}" gsettings set \
        org.gnome.system.location enabled false

    # Disable automatic problem reporting (sends crash data to Red Hat/GNOME)
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy report-technical-problems false

    # Disable sending usage statistics
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy send-software-usage-stats false

    # Stop retaining recent file history (reduces data exposure)
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy remember-recent-files false

    # Clear recent files automatically after N seconds (86400 = 1 day)
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy recent-files-max-age 1

    # Retain app usage history is used by GNOME Shell search ranking.
    # Disabling prevents building a profile of application usage.
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.privacy remember-app-usage false

    # -- Remote desktop (user level) -----------------------------------------

    # Disable RDP in GNOME Remote Desktop user settings
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.remote-desktop.rdp enable false 2>/dev/null || true

    # -- Screen lock ---------------------------------------------------------

    # Lock screen when display turns off (not just on idle)
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.screensaver lock-enabled true

    # Lock screen after 5 minutes of idle
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.screensaver lock-delay 300

    # Idle delay: blank screen after 5 minutes
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.session idle-delay 300

    # -- Notifications on lock screen ----------------------------------------

    # Hide notification content on lock screen (prevents shoulder surfing)
    run_as_user "${target_user}" gsettings set \
        org.gnome.desktop.notifications show-in-lock-screen false

    log "GNOME user settings applied for ${target_user}"
}

# ---------------------------------------------------------------------------
# GNOME dconf system locks
# Locks prevent users from overriding security-sensitive settings via
# the GNOME Settings UI or gsettings. Applied system-wide.
# ---------------------------------------------------------------------------

gnome_apply_dconf_locks() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would write dconf lock files to /etc/dconf/db/local.d/locks/"
        return 0
    fi

    log "Applying dconf system policy locks"

    mkdir --parents /etc/dconf/db/local.d /etc/dconf/db/local.d/locks

    # System-level defaults that supplement (but don't override) user settings
    write_file "/etc/dconf/db/local.d/00-secure-oss-privacy" \
"[org/gnome/system/location]
enabled=false

[org/gnome/desktop/privacy]
report-technical-problems=false
send-software-usage-stats=false
remember-recent-files=false

[org/gnome/desktop/remote-desktop/rdp]
enable=false"

    # Lock the location and remote desktop settings so they cannot be changed
    # from the UI. Comment out any lock you don't want to enforce.
    write_file "/etc/dconf/db/local.d/locks/secure-oss-locks" \
"/org/gnome/system/location/enabled
/org/gnome/desktop/remote-desktop/rdp/enable"

    # Recompile the dconf database to apply changes
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
