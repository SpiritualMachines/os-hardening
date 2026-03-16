#!/usr/bin/env bash
# optional/bash-lockdown.sh — Make user shell config files immutable
#
# Platform  : Fedora Silverblue (secureblue)
# Purpose   : Uses chattr +i to make shell initialization files immutable,
#             preventing LD_PRELOAD injection and environment variable hijacking
#             via ~/.bashrc, ~/.profile, etc. Mirrors the secureblue
#             ujust toggle-bash-environment-lockdown feature.
#
# WARNING   : This WILL break tooling that writes to shell config files:
#               - rustup, nvm, pyenv, sdkman, conda/mamba installers
#               - Some Flatpak shell integration scripts
#               - Package manager post-install hooks
#             Only enable this if you manage your shell config manually
#             and do not rely on installers modifying it.
#
# Usage:
#   sudo bash optional/bash-lockdown.sh [--user USERNAME] [--dry-run]
#   sudo bash optional/bash-lockdown.sh --unlock [--user USERNAME]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

TARGET_USER=""
UNLOCK_MODE=0

usage() {
    cat <<EOF
Usage: sudo bash optional/bash-lockdown.sh [OPTIONS]

Make user shell config files immutable to prevent environment hijacking.

Options:
  --user USERNAME   Target user (default: SUDO_USER or current user)
  --unlock          Remove immutable flag (unlock the files)
  --dry-run         Show what would be done without making changes
  --help            Show this help

WARNING: This breaks installer tools (rustup, nvm, conda, etc.) that modify
shell config files. Only use this if you manage shell config manually.
EOF
}

parse_args() {
    parse_common_args "$@"
    set -- "${REMAINING_ARGS[@]+"${REMAINING_ARGS[@]}"}"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user)
                TARGET_USER="${2:?--user requires a username}"
                shift 2
                ;;
            --unlock)
                UNLOCK_MODE=1
                shift
                ;;
            *)
                die "Unknown argument: $1"
                ;;
        esac
    done

    # Determine target user
    if [[ -z "${TARGET_USER}" ]]; then
        TARGET_USER="${SUDO_USER:-${USER}}"
    fi

    if [[ -z "${TARGET_USER}" ]] || ! id "${TARGET_USER}" &>/dev/null; then
        die "Cannot determine target user. Use --user USERNAME."
    fi
}

get_target_files() {
    local home
    home="$(getent passwd "${TARGET_USER}" | cut --delimiter=: --fields=6)"

    local files=(
        "${home}/.bashrc"
        "${home}/.bash_profile"
        "${home}/.bash_login"
        "${home}/.profile"
        "${home}/.bash_logout"
        "${home}/.zshrc"
        "${home}/.zprofile"
        "${home}/.zshenv"
        "${home}/.config/environment.d"
    )

    # Only return files/dirs that actually exist
    local existing=()
    for f in "${files[@]}"; do
        [[ -e "${f}" ]] && existing+=("${f}")
    done

    printf '%s\n' "${existing[@]+"${existing[@]}"}"
}

lock_files() {
    local home
    home="$(getent passwd "${TARGET_USER}" | cut --delimiter=: --fields=6)"

    warn "This will make shell config files immutable for user '${TARGET_USER}'."
    warn "Installer tools (rustup, nvm, conda, etc.) will FAIL to modify these files."
    warn ""
    warn "Press Ctrl+C within 5 seconds to abort."
    [[ "${DRY_RUN}" != "1" ]] && sleep 5

    while IFS= read -r file; do
        if [[ -d "${file}" ]]; then
            log "Locking directory: ${file}"
            run_cmd chattr +i --recursive "${file}"
        else
            log "Locking file: ${file}"
            run_cmd chattr +i "${file}"
        fi
    done < <(get_target_files)

    log "Shell config files locked for user '${TARGET_USER}'."
    log "To unlock: sudo bash optional/bash-lockdown.sh --unlock --user ${TARGET_USER}"
}

unlock_files() {
    log "Unlocking shell config files for user '${TARGET_USER}'"

    while IFS= read -r file; do
        if [[ -d "${file}" ]]; then
            log "Unlocking directory: ${file}"
            run_cmd chattr -i --recursive "${file}"
        else
            log "Unlocking file: ${file}"
            run_cmd chattr -i "${file}"
        fi
    done < <(get_target_files)

    log "Shell config files unlocked."
}

main() {
    parse_args "$@"
    require_root

    if ! command -v chattr &>/dev/null; then
        die "chattr not found. Install e2fsprogs or check your filesystem supports immutable flags."
    fi

    log "Target user: ${TARGET_USER}"

    if [[ "${UNLOCK_MODE}" -eq 1 ]]; then
        unlock_files
    else
        lock_files
    fi
}

main "$@"
