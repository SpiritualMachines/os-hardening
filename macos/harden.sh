#!/usr/bin/env bash
# harden.sh — Harden macOS
#
# Platform  : macOS 13 (Ventura) / 14 (Sonoma) / 15 (Sequoia)
# Purpose   : Applies Application Firewall hardening, pf AMT-port blocking,
#             remote access disabling, Siri disabling, telemetry/crash-reporter
#             blocking, MDM enrollment blocking, Spotlight suggestions disabling,
#             and AirDrop restriction.
# Tested on : macOS 13, macOS 14, macOS 15
# Requires  : sudo (root), provision.sh must be run first
#
# Usage:
#   sudo bash harden.sh [--dry-run] [--skip SECTIONS]
#
# Options:
#   --skip SECTIONS   Comma-separated list of sections to skip
#   --dry-run         Show what would be done without making changes
#   --help            Show this help
#
# Sections (--skip, comma-separated):
#   firewall   — Enable Application Firewall; block all incoming; stealth mode
#   pf         — Install pf anchor (AMT/ME port blocking) via LaunchDaemon
#   remote     — Disable SSH, Screen Sharing, Remote Management (ARD), Remote Apple Events
#   siri       — Disable Siri and voice trigger
#   telemetry  — Disable crash reporter, diagnostic submission; block Apple telemetry domains
#   mdm        — Block MDM/DEP enrollment domains in /etc/hosts
#   spotlight  — Disable Spotlight Suggestions and Look Up web queries
#   airdrop    — Restrict AirDrop to Contacts Only
#
# Verification:
#   firewall  : /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
#   pf        : sudo pfctl -a secure_oss -sr
#   remote    : sudo launchctl print-disabled system | grep -E 'sshd|screensharing|AEServer'
#   siri      : defaults read com.apple.Siri StatusMenuVisible
#   airdrop   : defaults read com.apple.sharingd DiscoverableMode

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# macOS major version integer (e.g. 13, 14, 15) — set in main()
MACOS_VERSION=""

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash harden.sh [OPTIONS]

Apply macOS security hardening baseline.

Options:
  --skip SECTIONS   Comma-separated list of sections to skip.
                    Available: firewall,pf,remote,siri,telemetry,mdm,spotlight,airdrop
  --dry-run         Show what would be done without making changes
  --help            Show this help

Run provision.sh before running this script.
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_args() {
    parse_common_args "$@"
    set -- "${REMAINING_ARGS[@]+"${REMAINING_ARGS[@]}"}"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip)
                IFS=',' read -ra SKIP_SECTIONS <<< "${2:?--skip requires a comma-separated list of section names}"
                shift 2
                ;;
            *)
                die "Unknown argument: $1. Run with --help for usage."
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Private helper: apply a domain blocklist to /etc/hosts
# Reads a domain list file and appends 0.0.0.0 entries to /etc/hosts.
# Idempotent: uses append_block with a named marker so re-runs replace the block.
# ---------------------------------------------------------------------------

_apply_hosts_block() {
    local domain_file="$1"
    local block_name="$2"

    if [[ ! -f "${domain_file}" ]]; then
        warn "Domain list file not found: ${domain_file} — skipping"
        return 0
    fi

    local entries=""
    while IFS= read -r line; do
        # Skip blank lines and comments
        [[ -z "${line}" ]] && continue
        [[ "${line}" =~ ^[[:space:]]*# ]] && continue
        entries+="0.0.0.0 ${line}"$'\n'
    done < "${domain_file}"

    if [[ -z "${entries}" ]]; then
        log "No domains to block in ${domain_file}"
        return 0
    fi

    local begin_marker="# BEGIN ${block_name}"
    local end_marker="# END ${block_name}"

    append_block "/etc/hosts" "${begin_marker}" "${end_marker}" "${entries%$'\n'}"
    local count
    count=$(echo "${entries}" | grep --count "^0\.0\.0\.0" || true)
    log "Applied hosts block '${block_name}' (${count} entries)"
}

# ---------------------------------------------------------------------------
# Section: Application Firewall
# macOS ships with two firewall mechanisms:
#   1. Application Firewall (socketfilterfw) — layer-7, per-application rules
#   2. pf — BSD packet filter (handled in the pf section below)
#
# The Application Firewall is the primary user-facing control. We enable it,
# set block-all incoming (equivalent to "Block all incoming connections" in
# System Settings > Network > Firewall), and enable stealth mode.
# ---------------------------------------------------------------------------

configure_firewall() {
    local SOCKETFILTER="/usr/libexec/ApplicationFirewall/socketfilterfw"

    if [[ ! -x "${SOCKETFILTER}" ]]; then
        die "socketfilterfw not found at ${SOCKETFILTER} — cannot configure Application Firewall"
    fi

    # Enable Application Firewall (the macOS layer-7 firewall).
    # This operates above pf and controls per-application inbound access.
    run_cmd "${SOCKETFILTER}" --setglobalstate on

    # Block all incoming connections. Applications must be explicitly allowed.
    # This is equivalent to "Block all incoming connections" in
    # System Settings > Network > Firewall.
    run_cmd "${SOCKETFILTER}" --setblockall on

    # Enable stealth mode: the system does not respond to ICMP ping requests or
    # connection attempts from closed TCP/UDP ports. This reduces network
    # fingerprinting and reconnaissance by not revealing which ports are closed
    # vs. which are filtered.
    run_cmd "${SOCKETFILTER}" --setstealthmode on

    # Enable logging to /var/log/appfirewall.log for audit purposes.
    run_cmd "${SOCKETFILTER}" --setloggingmode on
    run_cmd "${SOCKETFILTER}" --setloggingopt throttled

    log "Application Firewall enabled, block-all on, stealth on."
    log "Verify: ${SOCKETFILTER} --getglobalstate"
}

# ---------------------------------------------------------------------------
# Section: pf anchor (packet filter — AMT/ME port blocking)
# The pf anchor is installed as a LaunchDaemon rather than editing /etc/pf.conf
# directly. /etc/pf.conf may be SIP-protected on some macOS versions, and
# LaunchDaemon-based loading is more reliable across major OS upgrades.
#
# The anchor blocks Intel Active Management Technology (AMT) and IPMI ports.
# Note: AMT's shared-NIC mode intercepts packets below the OS; pf blocks
# OS-visible traffic only. Router/gateway-level blocking is the primary control.
# ---------------------------------------------------------------------------

configure_pf() {
    local ANCHOR_FILE="/etc/pf.anchors/secure_oss"
    local LAUNCHDAEMON_PLIST="/Library/LaunchDaemons/com.secure_oss.pf.plist"
    local SOURCE_ANCHOR="${SCRIPT_DIR}/lib/pf-anchor.conf"

    if [[ ! -f "${SOURCE_ANCHOR}" ]]; then
        die "pf anchor source file not found: ${SOURCE_ANCHOR}"
    fi

    # Install anchor rules file into the standard pf anchors directory
    run_cmd cp "${SOURCE_ANCHOR}" "${ANCHOR_FILE}"
    run_cmd chmod 644 "${ANCHOR_FILE}"

    # Install a LaunchDaemon that loads our anchor at boot.
    # This is more reliable than editing /etc/pf.conf (which may be SIP-protected).
    # The daemon runs pfctl to enable pf and load our named anchor.
    write_file "${LAUNCHDAEMON_PLIST}" '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.secure_oss.pf</string>
    <key>ProgramArguments</key>
    <array>
        <string>/sbin/pfctl</string>
        <string>-e</string>
        <string>-a</string>
        <string>secure_oss</string>
        <string>-f</string>
        <string>/etc/pf.anchors/secure_oss</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/secure_oss_pf.log</string>
</dict>
</plist>'

    run_cmd chmod 644 "${LAUNCHDAEMON_PLIST}"
    run_cmd chown root:wheel "${LAUNCHDAEMON_PLIST}"

    # Load the LaunchDaemon immediately (in addition to at-boot loading via RunAtLoad).
    # bootout first in case a previous version is already loaded.
    if [[ "${DRY_RUN}" != "1" ]]; then
        launchctl bootout system "${LAUNCHDAEMON_PLIST}" 2>/dev/null || true
        launchctl bootstrap system "${LAUNCHDAEMON_PLIST}"
    fi

    log "pf anchor installed and loaded."
    log "Verify: sudo pfctl -a secure_oss -sr"
}

# ---------------------------------------------------------------------------
# Section: Disable remote access services
# Disables all macOS remote access surfaces:
#   - SSH (Remote Login)
#   - Screen Sharing (VNC)
#   - Remote Management (Apple Remote Desktop / ARD)
#   - Remote Apple Events
#
# We use launchctl disable + bootout rather than systemsetup(8) because
# systemsetup -setremotelogin requires Full Disk Access permission on
# modern macOS and is deprecated as of macOS 13.
# ---------------------------------------------------------------------------

disable_remote_access() {
    local console_user
    console_user=$(get_console_user) || true

    # --- SSH (Remote Login) ---
    # launchctl disable persists the disabled state across reboots.
    # bootout stops the service immediately if it is currently running.
    log "Disabling Remote Login (SSH)..."
    run_cmd launchctl disable system/com.openssh.sshd
    run_cmd launchctl bootout system /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true

    # --- Screen Sharing (VNC) ---
    # Screen Sharing allows VNC-based remote desktop access. Disabled here;
    # can be re-enabled in System Settings > General > Sharing if needed.
    log "Disabling Screen Sharing..."
    run_cmd launchctl disable system/com.apple.screensharing
    run_cmd launchctl bootout system /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null || true

    # --- Remote Management (Apple Remote Desktop / ARD) ---
    # ARD is Apple's proprietary remote administration tool, used by IT teams
    # to manage fleets of Macs. kickstart -deactivate removes the ARD agent
    # and disables the service. This is the official Apple-recommended method.
    local ARD_KICKSTART="/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart"
    if [[ -x "${ARD_KICKSTART}" ]]; then
        log "Disabling Remote Management (ARD)..."
        run_cmd "${ARD_KICKSTART}" -deactivate -stop 2>/dev/null || true
    else
        warn "ARD kickstart tool not found at expected path — skipping ARD deactivation"
        warn "Disable manually: System Settings > General > Sharing > Remote Management"
    fi

    # --- Remote Apple Events ---
    # Remote Apple Events allow remote applications to send Apple Events (AppleScript
    # commands) to this Mac. Disabling this prevents unauthorized remote script
    # execution from other hosts on the network.
    log "Disabling Remote Apple Events..."
    run_cmd launchctl disable system/com.apple.AEServer
    run_cmd launchctl bootout system /System/Library/LaunchDaemons/com.apple.AEServer.plist 2>/dev/null || true

    log "All remote access services disabled."
    log "Verify: sudo launchctl print-disabled system | grep -E 'sshd|screensharing|AEServer'"
}

# ---------------------------------------------------------------------------
# Section: Disable Siri
# Full Siri disabling via CLI is inherently incomplete — Apple does not expose
# a single authoritative kill switch. We apply all known documented controls:
#   - System-wide assistant support preference (primary kill switch)
#   - User-level UI visibility defaults
#   - Voice trigger defaults
#   - Siri improvement opt-out preferences
#   - User LaunchAgent for the Siri model update daemon
#
# A reboot is required for all changes to take full effect.
# ---------------------------------------------------------------------------

disable_siri() {
    local console_user console_uid
    console_user=$(get_console_user) || {
        warn "Cannot determine console user — Siri user-level settings will be skipped."
        return 0
    }
    console_uid=$(get_console_user_uid) || true

    log "Disabling Siri for user: ${console_user}..."

    # Disable Siri at the system-wide assistant support level.
    # This is the primary kill switch — sets "Assistant Enabled = false" for
    # the entire system, affecting all users.
    run_cmd defaults write /Library/Preferences/com.apple.assistant.support \
        'Assistant Enabled' -bool false

    # User-level Siri visibility and status menu settings.
    # StatusMenuVisible=false removes the Siri icon from the menu bar.
    # VoiceTriggerUserEnabled=false disables the "Hey Siri" voice trigger.
    run_as_user "${console_user}" defaults write com.apple.Siri \
        StatusMenuVisible -bool false
    run_as_user "${console_user}" defaults write com.apple.Siri \
        VoiceTriggerUserEnabled -bool false
    run_as_user "${console_user}" defaults write com.apple.Siri \
        SiriPrefStashedStatusMenuVisible -bool false

    # Opt out of Siri data improvement programs.
    # These prefs control whether Siri sends interaction data to Apple for
    # training its models. Both must be false to opt out completely.
    run_as_user "${console_user}" defaults write com.apple.assistant.backedup \
        SiriCanLearnFromAppsByDefault -bool false
    run_as_user "${console_user}" defaults write com.apple.assistant.backedup \
        SiriImprovementsOptedIn -bool false

    # Stop and disable the Siri voice model update daemon (user-level LaunchAgent).
    # This daemon downloads updated Siri voice models in the background.
    # Failure is acceptable — the agent may not be loaded or may not exist on
    # all macOS versions. The || true guards prevent set -e from aborting.
    if [[ -n "${console_uid}" ]]; then
        run_cmd launchctl bootout "gui/${console_uid}/com.apple.siri.morphunassetsupdaterd" \
            2>/dev/null || true
        run_cmd launchctl disable "gui/${console_uid}/com.apple.siri.morphunassetsupdaterd" \
            2>/dev/null || true
    fi

    log "Siri disabled. A logout/login may be required for all changes to take effect."
    warn "Full Siri process termination requires a reboot."
}

# ---------------------------------------------------------------------------
# Section: Block telemetry
# Two-pronged approach:
#   1. Disable crash reporter and diagnostic submission daemons via launchctl
#   2. Block Apple analytics and third-party telemetry domains via /etc/hosts
# ---------------------------------------------------------------------------

block_telemetry() {
    local console_user console_uid
    console_user=$(get_console_user) || true
    console_uid=$(get_console_user_uid) || true

    # --- Crash Reporter settings ---
    # DialogType=none suppresses the crash dialog entirely, preventing the
    # user from inadvertently submitting crash reports to Apple.
    # UseUNC=0 disables the "Open with next application" crash option.
    if [[ -n "${console_user}" ]]; then
        run_as_user "${console_user}" defaults write com.apple.CrashReporter \
            DialogType none
        run_as_user "${console_user}" defaults write com.apple.CrashReporter \
            UseUNC 0
    fi

    # Disable automatic diagnostic submission at the system level.
    # DiagnosticMessagesHistory.plist is the system-wide crash submission config.
    # AutoSubmit=false prevents crash reports from being automatically sent to Apple.
    # ThirdPartyDataSubmit=false prevents third-party app data from being included.
    if [[ "${DRY_RUN}" != "1" ]]; then
        local diag_plist="/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist"
        mkdir -p "$(dirname "${diag_plist}")"
        /usr/libexec/PlistBuddy -c "Set :AutoSubmit false" "${diag_plist}" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :AutoSubmit bool false" "${diag_plist}" 2>/dev/null || true
        /usr/libexec/PlistBuddy -c "Set :ThirdPartyDataSubmit false" "${diag_plist}" 2>/dev/null || \
        /usr/libexec/PlistBuddy -c "Add :ThirdPartyDataSubmit bool false" "${diag_plist}" 2>/dev/null || true
    else
        echo "[DRY RUN] Would set AutoSubmit=false and ThirdPartyDataSubmit=false in DiagnosticMessagesHistory.plist"
    fi

    # Disable ReportCrash user agent.
    # This user-level LaunchAgent submits crash reports for user-space processes.
    if [[ -n "${console_uid}" ]]; then
        run_cmd launchctl bootout "gui/${console_uid}/com.apple.ReportCrash" 2>/dev/null || true
        run_cmd launchctl disable "gui/${console_uid}/com.apple.ReportCrash" 2>/dev/null || true
    fi

    # Disable ReportCrash system daemon.
    # This system-level daemon submits crash reports for system processes (root-owned).
    run_cmd launchctl bootout system/com.apple.ReportCrash.Root 2>/dev/null || true
    run_cmd launchctl disable system/com.apple.ReportCrash.Root 2>/dev/null || true

    # Disable SubmitDiagInfo — the daemon responsible for uploading collected
    # diagnostic information (crash logs, spin reports, sysdiagnose archives)
    # to Apple's servers on a periodic schedule.
    run_cmd launchctl bootout system/com.apple.SubmitDiagInfo 2>/dev/null || true
    run_cmd launchctl disable system/com.apple.SubmitDiagInfo 2>/dev/null || true

    # Disable DiagnosticReportSyncCopier — copies local crash reports into a
    # staging area for cloud upload by SubmitDiagInfo.
    run_cmd launchctl bootout system/com.apple.DiagnosticReportSyncCopier 2>/dev/null || true
    run_cmd launchctl disable system/com.apple.DiagnosticReportSyncCopier 2>/dev/null || true

    # --- Telemetry domain blocking ---
    # Null-routes known Apple analytics and third-party telemetry endpoints
    # via /etc/hosts so that even if daemons are re-enabled, submissions fail.
    _apply_hosts_block "${SCRIPT_DIR}/lib/hosts-telemetry.txt" "secure_oss-telemetry"

    # Flush DNS cache so the new /etc/hosts entries take effect immediately
    # without requiring a reboot.
    flush_dns_cache

    log "Telemetry blocking applied."
}

# ---------------------------------------------------------------------------
# Section: Block MDM enrollment domains
# Blocks MDM/DEP enrollment endpoints via /etc/hosts to prevent automatic
# MDM enrollment on non-supervised devices.
#
# IMPORTANT LIMITATION: Supervised devices enrolled via Apple Business Manager
# or Apple School Manager use hardware-level enrollment tied to the device
# serial number in Apple's servers. Hosts-file blocking alone is insufficient
# for supervised devices — it only protects non-supervised personal devices.
# ---------------------------------------------------------------------------

block_mdm() {
    # Block MDM and DEP enrollment endpoints via /etc/hosts.
    # This prevents automatic MDM enrollment on non-supervised devices.
    _apply_hosts_block "${SCRIPT_DIR}/lib/hosts-mdm.txt" "secure_oss-mdm"
    flush_dns_cache
    log "MDM enrollment domain blocking applied."
    log "Note: supervised devices require hardware-level unenrollment from Apple Business Manager."
}

# ---------------------------------------------------------------------------
# Section: Disable Spotlight Suggestions
# Spotlight Suggestions sends search queries to Apple for web-based results.
# "Look Up" (dictionary/web lookup of selected text) can also phone home.
# We disable network-dependent Spotlight categories while preserving local
# search (Applications, Documents, etc.) which has no privacy impact.
# ---------------------------------------------------------------------------

disable_spotlight_suggestions() {
    local console_user
    console_user=$(get_console_user) || {
        warn "Cannot determine console user — Spotlight settings will be skipped."
        return 0
    }

    log "Disabling Spotlight web suggestions for user: ${console_user}..."

    # Disable Look Up suggestions.
    # "Look Up" sends selected text to Apple for dictionary/web lookup results.
    run_as_user "${console_user}" defaults write com.apple.lookup.shared \
        LookupSuggestionsDisabled -bool true 2>/dev/null || true

    # Disable Safari's universal search bar (sends queries to Apple/Google)
    # and suppress Safari's search suggestions dropdown.
    run_as_user "${console_user}" defaults write com.apple.Safari \
        UniversalSearchEnabled -bool false 2>/dev/null || true
    run_as_user "${console_user}" defaults write com.apple.Safari \
        SuppressSearchSuggestions -bool true 2>/dev/null || true

    # Configure Spotlight orderedItems to disable network-dependent categories
    # while keeping all local-only search categories enabled.
    #
    # Disabled categories:
    #   SIRI_NATURAL_LANGUAGE_SUGGESTIONS — sends queries to Apple Siri backend
    #   SUGGESTIONS                       — Siri Suggestions / web results
    #   CONTACT, BOOKMARKS, EVENT_TODO    — sensitive personal data categories
    #   MESSAGES, TIPS, DEFINITION        — network/Siri-integrated categories
    #
    # Enabled categories: local Applications, Documents, PDFs, Images, etc.
    run_as_user "${console_user}" defaults write com.apple.Spotlight orderedItems -array \
        '{"enabled" = 1;"name" = "APPLICATIONS";}' \
        '{"enabled" = 1;"name" = "SYSTEM_PREFS";}' \
        '{"enabled" = 1;"name" = "DIRECTORIES";}' \
        '{"enabled" = 1;"name" = "PDF";}' \
        '{"enabled" = 1;"name" = "DOCUMENTS";}' \
        '{"enabled" = 1;"name" = "SPREADSHEETS";}' \
        '{"enabled" = 1;"name" = "PRESENTATIONS";}' \
        '{"enabled" = 1;"name" = "CALCULATOR";}' \
        '{"enabled" = 1;"name" = "IMAGES";}' \
        '{"enabled" = 1;"name" = "MOVIES";}' \
        '{"enabled" = 1;"name" = "MUSIC";}' \
        '{"enabled" = 1;"name" = "SOURCE";}' \
        '{"enabled" = 1;"name" = "FONTS";}' \
        '{"enabled" = 0;"name" = "CONTACT";}' \
        '{"enabled" = 0;"name" = "BOOKMARKS";}' \
        '{"enabled" = 0;"name" = "EVENT_TODO";}' \
        '{"enabled" = 0;"name" = "MESSAGES";}' \
        '{"enabled" = 0;"name" = "TIPS";}' \
        '{"enabled" = 0;"name" = "DEFINITION";}' \
        '{"enabled" = 0;"name" = "SIRI_NATURAL_LANGUAGE_SUGGESTIONS";}' \
        '{"enabled" = 0;"name" = "SUGGESTIONS";}' 2>/dev/null || true

    # Restart the Spotlight indexer process to apply the orderedItems change.
    # Spotlight will automatically restart; search remains functional.
    run_cmd killall Spotlight 2>/dev/null || true

    log "Spotlight suggestions disabled."
    warn "Verify: System Settings > Siri & Spotlight > Search Results — 'Siri Suggestions' should be unchecked."
}

# ---------------------------------------------------------------------------
# Section: Restrict AirDrop
# AirDrop "Everyone" mode allows any nearby Apple device to send files to this
# Mac without authentication. We restrict to "Contacts Only" which requires
# the sender to be in the user's Contacts — a reasonable security vs. usability
# balance. "No One" would disable AirDrop entirely; that is left as a manual
# choice for users who want it.
# ---------------------------------------------------------------------------

restrict_airdrop() {
    local console_user
    console_user=$(get_console_user) || {
        warn "Cannot determine console user — AirDrop settings will be skipped."
        return 0
    }

    log "Restricting AirDrop to Contacts Only for user: ${console_user}..."

    # Set AirDrop discoverability to "Contacts Only".
    # Valid values: "Everyone", "Contacts Only", "No One"
    # "Contacts Only" requires the sender to be in the user's Contacts app,
    # preventing arbitrary strangers from AirDropping files to this device.
    run_as_user "${console_user}" defaults write com.apple.sharingd \
        DiscoverableMode -string "Contacts Only"

    # Restart the sharing daemon so the new DiscoverableMode takes effect
    # immediately without requiring a logout.
    run_cmd killall sharingd 2>/dev/null || true

    log "AirDrop restricted to Contacts Only."
    log "Verify: defaults read com.apple.sharingd DiscoverableMode"
}

# ---------------------------------------------------------------------------
# Gatekeeper verification (called before sections, not a skippable section)
# On macOS 13-14: re-enable Gatekeeper if disabled.
# On macOS 15: CLI management is not available; warn and direct to UI.
# ---------------------------------------------------------------------------

_verify_gatekeeper() {
    log "Checking Gatekeeper status..."
    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")

    if echo "${gk_status}" | grep --quiet "enabled"; then
        log "Gatekeeper: enabled"
    elif [[ "${MACOS_VERSION}" -ge 15 ]]; then
        warn "Gatekeeper status: ${gk_status}"
        warn "On macOS 15 (Sequoia), CLI Gatekeeper management is not supported."
        warn "Verify Gatekeeper is enabled: System Settings > Privacy & Security > Security"
    else
        warn "Gatekeeper appears disabled. Re-enabling..."
        run_cmd spctl --master-enable
        log "Gatekeeper re-enabled."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    mkdir -p /var/log
    log "=== secure_oss macOS harden.sh v${SCRIPT_VERSION} ==="

    require_root
    require_macos
    require_min_macos_version 13

    MACOS_VERSION=$(get_macos_major_version)
    log "macOS major version: ${MACOS_VERSION}"

    # Verify Gatekeeper before applying any hardening sections.
    # This is a preflight check, not a skippable section.
    _verify_gatekeeper

    run_section "firewall"  configure_firewall
    run_section "pf"        configure_pf
    run_section "remote"    disable_remote_access
    run_section "siri"      disable_siri
    run_section "telemetry" block_telemetry
    run_section "mdm"       block_mdm
    run_section "spotlight" disable_spotlight_suggestions
    run_section "airdrop"   restrict_airdrop

    echo ""
    log "=== harden.sh complete ==="

    if [[ "${_FAILED}" -ne 0 ]]; then
        warn "One or more sections encountered errors. Review the output above."
    fi

    reboot_notice "Some settings (Siri, Spotlight, remote access) require a reboot to fully apply."
}

main "$@"
