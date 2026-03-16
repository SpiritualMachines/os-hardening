#!/usr/bin/env bash
# provision.sh — Rebase Fedora Silverblue to secureblue
#
# Platform  : Fedora Silverblue (any variant)
# Purpose   : Detects the current OCI deployment, rebases to the appropriate
#             secureblue image, and stages any required rpm-ostree package
#             changes. Exits after staging — a reboot is required before
#             running harden.sh.
# Tested on : Fedora Silverblue 41
# Requires  : root, Fedora Atomic / Silverblue, internet access
#
# Usage:
#   sudo bash provision.sh [--dry-run] [--image IMAGE_VARIANT]
#
# Image variants (default: silverblue-main):
#   silverblue-main          GNOME desktop
#   silverblue-nvidia-main   GNOME desktop with NVIDIA proprietary drivers
#   kinoite-main             KDE Plasma desktop
#   kinoite-nvidia-main      KDE Plasma with NVIDIA drivers
#
# After running this script, reboot and then run:
#   sudo bash harden.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SECUREBLUE_REGISTRY="ghcr.io/secureblue"
DEFAULT_IMAGE="silverblue-main"
SELECTED_IMAGE=""

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash provision.sh [OPTIONS]

Rebase Fedora Silverblue to the secureblue hardened image.

Options:
  --image IMAGE   secureblue image variant to use (default: ${DEFAULT_IMAGE})
                  Options: silverblue-main, silverblue-nvidia-main,
                           kinoite-main, kinoite-nvidia-main
  --dry-run       Show what would be done without making changes
  --help          Show this help

After this script completes, reboot and run:
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
            --image)
                SELECTED_IMAGE="${2:?--image requires a value}"
                shift 2
                ;;
            *)
                die "Unknown argument: $1. Run with --help for usage."
                ;;
        esac
    done

    SELECTED_IMAGE="${SELECTED_IMAGE:-${DEFAULT_IMAGE}}"
}

# ---------------------------------------------------------------------------
# NVIDIA detection
# ---------------------------------------------------------------------------

has_nvidia_gpu() {
    lspci 2>/dev/null | grep --quiet --ignore-case "nvidia"
}

suggest_nvidia_image() {
    local base_image="$1"
    echo "${base_image/%-main/-nvidia-main}"
}

check_nvidia_mismatch() {
    if has_nvidia_gpu && [[ "${SELECTED_IMAGE}" != *nvidia* ]]; then
        warn "NVIDIA GPU detected but a non-NVIDIA image is selected (${SELECTED_IMAGE})."
        warn "After rebase, NVIDIA drivers may not be available."
        warn "Consider using: --image $(suggest_nvidia_image "${SELECTED_IMAGE}")"
        warn "Continuing with selected image in 5 seconds. Press Ctrl+C to abort."
        sleep 5
    fi
}

# ---------------------------------------------------------------------------
# Image detection
# ---------------------------------------------------------------------------

get_current_image_ref() {
    # Returns the container image reference of the active deployment, or empty string
    if command -v bootc &>/dev/null; then
        bootc status --format json 2>/dev/null \
            | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('status', {}).get('booted', {}).get('image', {}).get('image', {}).get('image', ''))
except Exception:
    print('')
" 2>/dev/null || true
    else
        rpm-ostree status --json 2>/dev/null \
            | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ref = d['deployments'][0].get('container-image-reference', '')
    print(ref)
except Exception:
    print('')
" 2>/dev/null || true
    fi
}

is_already_secureblue() {
    local current_image
    current_image="$(get_current_image_ref)"
    [[ "${current_image}" == *"secureblue"* ]]
}

# ---------------------------------------------------------------------------
# Rebase
# ---------------------------------------------------------------------------

perform_rebase() {
    local target_image="${SECUREBLUE_REGISTRY}/${SELECTED_IMAGE}:latest"

    log "Target image: ${target_image}"

    if command -v bootc &>/dev/null; then
        log "Using bootc to switch image (preferred method)"
        run_cmd bootc switch "${target_image}"
    else
        warn "bootc not found — falling back to rpm-ostree rebase (legacy path)"
        warn "Consider upgrading to a Fedora 40+ base before rebasing."
        # Two-step rebase: first unverified to get the secureblue signing keys,
        # then verified. The reboot between steps happens naturally since provision.sh
        # exits after this call and the user is instructed to reboot.
        run_cmd rpm-ostree rebase "ostree-unverified-registry:docker://${target_image}"
        warn "After rebooting, run provision.sh again to switch to the signed/verified image."
        warn "Then reboot once more before running harden.sh."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    mkdir --parents /var/log
    log "=== secure_oss provision.sh v${SCRIPT_VERSION} ==="
    log "Selected image variant: ${SELECTED_IMAGE}"

    require_root
    require_silverblue

    # If a reboot is still pending from a previous run, stop here
    check_reboot_pending

    # Check for NVIDIA mismatch before anything destructive
    check_nvidia_mismatch

    # -----------------------------------------------------------------
    # Already on secureblue?
    # -----------------------------------------------------------------
    if is_already_secureblue; then
        log "Active deployment is already a secureblue image."
        log "If you need to update or change the image variant, run:"
        log "  bootc switch ${SECUREBLUE_REGISTRY}/${SELECTED_IMAGE}:latest"
        log ""
        log "To continue with post-rebase hardening, run:"
        log "  sudo bash harden.sh"
        exit 0
    fi

    banner "Rebasing to secureblue"
    log "Current image: $(get_current_image_ref || echo '(vanilla Silverblue or unknown)')"
    log ""
    log "This will stage a rebase to secureblue. Your current system will not"
    log "be changed until you reboot. All your files and Flatpaks are preserved."
    log ""

    if [[ "${DRY_RUN}" != "1" ]]; then
        log "Starting rebase in 5 seconds. Press Ctrl+C to abort."
        sleep 5
    fi

    perform_rebase

    # -----------------------------------------------------------------
    # Post-rebase: set sentinel and instruct the user to reboot
    # -----------------------------------------------------------------
    if [[ "${DRY_RUN}" != "1" ]]; then
        set_reboot_pending "secureblue rebase staged — must reboot before running harden.sh"
    fi

    reboot_notice "secureblue rebase staged"
    log "After rebooting, run: sudo bash ${SCRIPT_DIR}/harden.sh"
}

main "$@"
