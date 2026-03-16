#!/usr/bin/env bash
# optional/disable-webcam.sh — Disable USB webcam at the kernel module level
#
# Platform  : Fedora Silverblue (secureblue)
# Purpose   : Blacklists the uvcvideo kernel module, preventing any UVC-compliant
#             USB webcam from being used. This is a privacy measure for users who
#             do not use a webcam or want hardware-level assurance it cannot be
#             activated by software.
#
# WARNING   : This will break all UVC webcams (the vast majority of USB webcams).
#             Video conferencing (Zoom, Teams, Meet) will lose camera access.
#             To re-enable: sudo bash optional/disable-webcam.sh --enable
#
# Usage:
#   sudo bash optional/disable-webcam.sh [--dry-run]
#   sudo bash optional/disable-webcam.sh --enable   (re-enable webcam)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

CONF_FILE="/etc/modprobe.d/secure-oss-webcam.conf"
ENABLE_MODE=0

usage() {
    cat <<EOF
Usage: sudo bash optional/disable-webcam.sh [OPTIONS]

Disable or re-enable USB webcam (uvcvideo kernel module).

Options:
  --enable    Re-enable webcam (remove the blacklist)
  --dry-run   Show what would be done without making changes
  --help      Show this help
EOF
}

parse_args() {
    parse_common_args "$@"
    set -- "${REMAINING_ARGS[@]+"${REMAINING_ARGS[@]}"}"
    for arg in "$@"; do
        [[ "${arg}" == "--enable" ]] && ENABLE_MODE=1
    done
}

disable_webcam() {
    if [[ -f "${CONF_FILE}" ]]; then
        log "Webcam already disabled via ${CONF_FILE} — skipping"
        log "To re-enable: sudo bash optional/disable-webcam.sh --enable"
        return 0
    fi

    warn "This will disable ALL UVC webcams at the kernel module level."
    warn "This includes virtually all USB webcams and many built-in laptop cameras."
    warn "Video conferencing applications will lose camera access."
    warn ""
    warn "Press Ctrl+C within 5 seconds to abort."
    [[ "${DRY_RUN}" != "1" ]] && sleep 5

    write_file "${CONF_FILE}" "# secure_oss: Disable UVC webcam module
# Blacklists the uvcvideo driver to prevent any UVC-compliant webcam from
# functioning. Hardware-level privacy measure.
# To re-enable: sudo bash optional/disable-webcam.sh --enable
blacklist uvcvideo
install uvcvideo /bin/false"

    # Unload the module if currently loaded
    if lsmod 2>/dev/null | grep --quiet "uvcvideo"; then
        log "Unloading uvcvideo module from running kernel..."
        run_cmd modprobe --remove uvcvideo 2>/dev/null || \
            warn "Could not unload uvcvideo — it may be in use. Reboot to apply."
    fi

    log "Webcam disabled. Reboot to ensure the module does not reload."
}

enable_webcam() {
    if [[ ! -f "${CONF_FILE}" ]]; then
        log "Webcam blacklist not present — webcam is already enabled."
        return 0
    fi

    log "Re-enabling webcam (removing ${CONF_FILE})"
    run_cmd rm --force "${CONF_FILE}"
    run_cmd modprobe uvcvideo 2>/dev/null || \
        warn "Could not load uvcvideo — reboot to fully restore webcam."
    log "Webcam re-enabled."
}

main() {
    parse_args "$@"
    require_root

    if [[ "${ENABLE_MODE}" -eq 1 ]]; then
        enable_webcam
    else
        disable_webcam
    fi
}

main "$@"
