#!/usr/bin/env bash
# provision.sh — Preflight checks and prerequisites for macOS hardening
#
# Platform  : macOS 13 (Ventura) / 14 (Sonoma) / 15 (Sequoia)
# Purpose   : Verify prerequisites, report current security posture, and prepare
#             the system for harden.sh. Unlike Linux scripts, this does not install
#             packages — it checks and reports only, with one active change:
#             re-enabling Gatekeeper if it has been disabled (macOS 13–14 only).
# Tested on : macOS 13, macOS 14, macOS 15
# Requires  : sudo (root for marker directory creation and Gatekeeper re-enable)
#
# Usage:
#   sudo bash provision.sh [--dry-run]
#
# After this script completes, run:
#   sudo bash harden.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# ---------------------------------------------------------------------------
# Results accumulator — used for the final summary table
# ---------------------------------------------------------------------------

declare -A _POSTURE_RESULTS=()

_record() {
    # Record a posture check result.
    # Usage: _record KEY "status string"
    _POSTURE_RESULTS["$1"]="$2"
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash provision.sh [OPTIONS]

Preflight checks and prerequisites for macOS hardening.

Options:
  --dry-run   Show what would be done without making changes
  --help      Show this help

After this script completes, run:
  sudo bash harden.sh
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
            *)
                die "Unknown argument: $1. Run with --help for usage."
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Section: macOS version check
# Require macOS 13 (Ventura) or later. Earlier versions lack several of the
# launchctl primitives and defaults keys used by harden.sh.
# ---------------------------------------------------------------------------

check_macos_version() {
    banner "macOS Version Check"

    local ver
    ver=$(sw_vers -productVersion)
    local major
    major=$(echo "${ver}" | cut -d. -f1)
    local build
    build=$(sw_vers -buildVersion)

    log "macOS version  : ${ver}"
    log "Build          : ${build}"

    if [[ "${major}" -lt 13 ]]; then
        _record "macOS version" "FAIL — ${ver} (13+ required)"
        die "macOS 13 (Ventura) or later is required. Detected: ${ver}"
    else
        _record "macOS version" "OK — ${ver}"
        log "Version check passed."
    fi
}

# ---------------------------------------------------------------------------
# Section: SIP status check
# System Integrity Protection prevents root-level modifications to protected
# system directories and processes. These scripts are designed to operate
# within SIP constraints — they do not attempt to disable SIP.
#
# SIP can only be changed from Recovery Mode (Command+R at boot). This check
# reports the status and warns if SIP is disabled; it does not attempt to
# enable it (that would require a reboot into Recovery Mode).
# ---------------------------------------------------------------------------

check_sip_status() {
    banner "System Integrity Protection (SIP)"

    local sip_output
    sip_output=$(csrutil status 2>/dev/null || echo "unknown")

    log "csrutil status: ${sip_output}"

    if echo "${sip_output}" | grep --quiet "enabled"; then
        _record "SIP" "OK — enabled"
        log "SIP is enabled."
    else
        _record "SIP" "WARNING — disabled or unknown"
        warn "SIP appears to be disabled or its status could not be determined."
        warn "SIP can only be re-enabled from macOS Recovery Mode:"
        warn "  1. Restart your Mac and hold Command+R (Intel) or power button (Apple Silicon)"
        warn "  2. Open Terminal in Recovery and run: csrutil enable"
        warn "  3. Restart normally"
        warn "Proceeding without SIP does not block harden.sh, but is not recommended."
    fi
}

# ---------------------------------------------------------------------------
# Section: FileVault check
# FileVault provides full-disk encryption for the startup volume.
# Enabling it requires user interaction to generate and save a recovery key.
# This script cannot enable FileVault silently — it reports the status and
# provides manual instructions.
# ---------------------------------------------------------------------------

check_filevault() {
    banner "FileVault (Full-Disk Encryption)"

    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "unknown")

    log "fdesetup status: ${fv_status}"

    if echo "${fv_status}" | grep --quiet -i "on"; then
        _record "FileVault" "OK — enabled"
        log "FileVault is enabled."
    elif echo "${fv_status}" | grep --quiet -i "off"; then
        _record "FileVault" "WARNING — disabled"
        warn "FileVault is NOT enabled. Your startup disk is unencrypted."
        warn ""
        warn "To enable FileVault:"
        warn "  Option A (command line):"
        warn "    sudo fdesetup enable"
        warn "    (You will be prompted to save a recovery key — store it securely.)"
        warn ""
        warn "  Option B (GUI):"
        warn "    System Settings > Privacy & Security > FileVault > Turn On..."
        warn ""
        warn "A reboot is required after enabling FileVault."
    else
        _record "FileVault" "UNKNOWN — ${fv_status}"
        warn "Could not determine FileVault status: ${fv_status}"
    fi
}

# ---------------------------------------------------------------------------
# Section: Gatekeeper check and conditional re-enable
# Gatekeeper enforces code signing and notarization checks on downloaded apps.
# If disabled, re-enable it here.
#
# macOS 15 (Sequoia) removed the spctl --master-enable CLI command — Gatekeeper
# can only be managed from System Settings on Sequoia. On macOS 13 and 14 we
# can re-enable it programmatically.
# ---------------------------------------------------------------------------

check_gatekeeper() {
    banner "Gatekeeper"

    local macos_major
    macos_major=$(get_macos_major_version)

    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "unknown")

    log "spctl --status: ${gk_status}"

    if echo "${gk_status}" | grep --quiet "enabled"; then
        _record "Gatekeeper" "OK — enabled"
        log "Gatekeeper is enabled."
        return 0
    fi

    # Gatekeeper is disabled or unknown
    if [[ "${macos_major}" -ge 15 ]]; then
        # macOS 15 Sequoia removed spctl --master-enable
        _record "Gatekeeper" "WARNING — disabled (manual re-enable required on macOS 15)"
        warn "Gatekeeper appears disabled."
        warn "On macOS 15 (Sequoia), CLI Gatekeeper management was removed by Apple."
        warn "Re-enable manually:"
        warn "  System Settings > Privacy & Security > Security"
        warn "  Set 'Allow applications from' to 'App Store and identified developers'"
    else
        # macOS 13 or 14 — re-enable via CLI
        _record "Gatekeeper" "FIXED — was disabled, re-enabled"
        warn "Gatekeeper is disabled. Re-enabling..."
        run_cmd spctl --master-enable
        log "Gatekeeper re-enabled."
    fi
}

# ---------------------------------------------------------------------------
# Section: Xcode Command Line Tools check
# Python 3 (required by the append_block function in common.sh) is provided
# by the Xcode Command Line Tools on macOS. Homebrew is NOT required.
#
# If CLT is missing, we trigger the installation prompt and ask the user to
# re-run provision.sh after completing the GUI installer.
# ---------------------------------------------------------------------------

install_xcode_cli_tools() {
    banner "Xcode Command Line Tools"

    if xcode-select -p &>/dev/null; then
        local xcode_path
        xcode_path=$(xcode-select -p)
        _record "Xcode CLI Tools" "OK — ${xcode_path}"
        log "Xcode Command Line Tools are installed at: ${xcode_path}"
        return 0
    fi

    _record "Xcode CLI Tools" "MISSING — installation triggered"
    warn "Xcode Command Line Tools are not installed."
    warn "They provide Python 3, which is required by harden.sh."
    warn ""

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would run: xcode-select --install"
        warn "[DRY RUN] Re-run provision.sh after installing Xcode Command Line Tools."
        return 0
    fi

    # xcode-select --install opens a GUI dialog — it cannot be fully automated.
    # We trigger it and then exit with instructions. The user must re-run
    # provision.sh after completing the installation.
    log "Triggering Xcode Command Line Tools installation dialog..."
    xcode-select --install 2>/dev/null || true

    echo ""
    warn "=========================================================="
    warn "  Action required: Complete the Xcode CLI Tools installer"
    warn "  that just appeared on screen, then re-run:"
    warn "    sudo bash provision.sh"
    warn "=========================================================="
    exit 0
}

# ---------------------------------------------------------------------------
# Section: Create marker directory
# The marker directory tracks which harden.sh sections have been applied,
# enabling idempotent re-runs.
# ---------------------------------------------------------------------------

create_marker_directory() {
    banner "Marker Directory"

    if [[ -d "${MARKER_DIR}" ]]; then
        log "Marker directory already exists: ${MARKER_DIR}"
        _record "Marker directory" "OK — already exists"
        return 0
    fi

    log "Creating marker directory: ${MARKER_DIR}"
    run_cmd mkdir -p "${MARKER_DIR}"
    _record "Marker directory" "OK — created"
}

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

_print_summary() {
    echo ""
    echo -e "${_BOLD}${_CYAN}╔══════════════════════════════════════════════════════════════════╗"
    printf "║  %-64s  ║\n" "Security Posture Summary"
    echo "╠══════════════════════════════════════════════════════════════════╣"
    printf "║  %-30s  %-33s║\n" "Check" "Result"
    echo "╠══════════════════════════════════════════════════════════════════╣"
    for key in "macOS version" "SIP" "FileVault" "Gatekeeper" "Xcode CLI Tools" "Marker directory"; do
        local result="${_POSTURE_RESULTS[${key}]:-N/A}"
        printf "║  %-30s  %-33s║\n" "${key}" "${result}"
    done
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${_RESET}"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    mkdir -p /var/log
    log "=== secure_oss macOS provision.sh v${SCRIPT_VERSION} ==="

    require_root
    require_macos

    check_macos_version
    check_sip_status
    check_filevault
    check_gatekeeper
    install_xcode_cli_tools
    create_marker_directory

    _print_summary

    echo ""
    log "=== provision.sh complete ==="
    log ""
    log "Next step: sudo bash ${SCRIPT_DIR}/harden.sh"
    log "  Options: --skip SECTIONS  --dry-run"
    echo ""
}

main "$@"
