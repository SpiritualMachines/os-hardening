#!/usr/bin/env bash
# lib/kde.sh — KDE Plasma-specific hardening functions
# Sourced by harden.sh when DE=kde; not executed directly.
#
# Applies privacy and security settings specific to KDE Plasma and its
# associated services. Settings are applied at both the system level
# (systemctl) and the user level (kwriteconfig5 via sudo -u).

# ---------------------------------------------------------------------------
# KDE system-level service hardening
# ---------------------------------------------------------------------------

kde_harden_services() {
    log "Hardening KDE system services"

    # KRFB is KDE's VNC server (Desktop Sharing). Masking prevents remote
    # access via VNC even if the user enables it in System Settings.
    for krfb_unit in krfb.service krfb.socket; do
        if systemctl cat "${krfb_unit}" &>/dev/null; then
            log "Masking ${krfb_unit} (KDE VNC/desktop sharing server)"
            run_cmd systemctl mask "${krfb_unit}"
            run_cmd systemctl stop "${krfb_unit}" 2>/dev/null || true
        fi
    done

    # GeoClue provides location services. Masking prevents any application
    # from obtaining location data via the portal.
    if systemctl cat geoclue.service &>/dev/null; then
        log "Masking geoclue.service (location services)"
        run_cmd systemctl mask geoclue.service
    fi

    # Baloo is KDE's file indexer. Unlike GNOME Tracker, Baloo runs as a
    # user service. We disable it at the user level in kde_harden_user_settings.
    # System-level: ensure baloo_file.service user unit is masked globally.
    if systemctl --global cat baloo_file.service &>/dev/null; then
        log "Globally disabling baloo_file.service (file indexer)"
        run_cmd systemctl --global disable baloo_file.service 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# KDE user-level privacy settings
# Applied via kwriteconfig5 for the calling (non-root) user.
# kwriteconfig5 writes directly to ~/.config KDE config files.
# ---------------------------------------------------------------------------

kde_harden_user_settings() {
    local target_user
    target_user="$(get_sudo_user)" || {
        warn "Skipping user-level KDE settings — could not determine user"
        return 0
    }

    local user_home
    user_home="$(getent passwd "${target_user}" | cut --delimiter=: --fields=6)"

    log "Applying KDE privacy settings for user: ${target_user}"

    # -- KDE User Feedback (kuserfeedback) -----------------------------------
    # Plasma's telemetry system. Level 0 = no data sent.
    # Config file: ~/.config/KDE/UserFeedback.conf
    run_as_user "${target_user}" kwriteconfig5 \
        --file "${user_home}/.config/KDE/UserFeedback.conf" \
        --group "Global" \
        --key "FeedbackLevel" "0" 2>/dev/null || \
        warn "kwriteconfig5 not available — KDE UserFeedback level not set"

    # -- KDE Connect ---------------------------------------------------------
    # KDE Connect provides phone-desktop integration over the local network.
    # It is NOT a remote administration tool, but it does open a local port
    # and can share clipboard content. We disable the port-listening mode
    # by disabling the daemon. Users who want KDE Connect can re-enable it.
    if systemctl --user --machine="${target_user}@" cat kdeconnectd.service \
        &>/dev/null 2>&1; then
        run_as_user "${target_user}" systemctl --user disable --now kdeconnectd.service \
            2>/dev/null || warn "Could not disable kdeconnectd.service for ${target_user}"
    fi

    # Alternatively, block KDE Connect firewall rules if the daemon is running
    # (belt-and-suspenders: firewall zone has already removed all services,
    # but this explicitly removes KDE Connect service if it was added)
    run_cmd firewall-cmd --remove-service=kdeconnect --permanent 2>/dev/null || true

    # -- Baloo file indexer --------------------------------------------------
    # Disable Baloo file indexing. Baloo reads all files and their metadata.
    run_as_user "${target_user}" balooctl6 disable 2>/dev/null || \
    run_as_user "${target_user}" balooctl disable 2>/dev/null || \
        warn "balooctl not available — Baloo indexer not disabled via CLI"

    # Also write the config directly as fallback
    run_as_user "${target_user}" kwriteconfig5 \
        --file "${user_home}/.config/baloofilerc" \
        --group "Basic Settings" \
        --key "Indexing-Enabled" "false" 2>/dev/null || true

    # -- Screen locking ------------------------------------------------------
    run_as_user "${target_user}" kwriteconfig5 \
        --file "${user_home}/.config/kscreenlockerrc" \
        --group "Daemon" \
        --key "Autolock" "true" 2>/dev/null || true

    # Lock after 5 minutes of inactivity (value in minutes)
    run_as_user "${target_user}" kwriteconfig5 \
        --file "${user_home}/.config/kscreenlockerrc" \
        --group "Daemon" \
        --key "Timeout" "5" 2>/dev/null || true

    # -- Location services ---------------------------------------------------
    run_as_user "${target_user}" kwriteconfig5 \
        --file "${user_home}/.config/plasma-localerc" \
        --group "Formats" \
        --key "LANG" "$(locale | grep LANG | cut -d= -f2)" 2>/dev/null || true

    # Disable location in Plasma (uses GeoClue which we already masked)
    run_as_user "${target_user}" kwriteconfig5 \
        --file "${user_home}/.config/plasma-nm" \
        --group "General" \
        --key "EnableGPS" "false" 2>/dev/null || true

    # -- Recent files / activity history -------------------------------------
    # KDE Activities can track file usage. Disable recent document tracking.
    run_as_user "${target_user}" kwriteconfig5 \
        --file "${user_home}/.config/kactivitymanagerdrc" \
        --group "Plugins" \
        --key "org.kde.ActivityManager.Resources.Scoring.enabledPlugin" "false" \
        2>/dev/null || true

    # -- Clipboard history ---------------------------------------------------
    # Klipper (KDE clipboard manager) retains clipboard history.
    # Disable history to prevent sensitive data persisting in clipboard.
    run_as_user "${target_user}" kwriteconfig5 \
        --file "${user_home}/.config/klipperrc" \
        --group "General" \
        --key "KeepClipboardContents" "false" 2>/dev/null || true

    run_as_user "${target_user}" kwriteconfig5 \
        --file "${user_home}/.config/klipperrc" \
        --group "General" \
        --key "MaxClipItems" "1" 2>/dev/null || true

    log "KDE user settings applied for ${target_user}"
}

# ---------------------------------------------------------------------------
# Main entry point — called by harden.sh
# ---------------------------------------------------------------------------

harden_kde() {
    kde_harden_services
    kde_harden_user_settings
}
