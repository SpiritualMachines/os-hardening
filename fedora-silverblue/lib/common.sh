#!/usr/bin/env bash
# lib/common.sh — Shared utilities for secure_oss Silverblue scripts
# Sourced by provision.sh and harden.sh; not executed directly.
#
# Platform : Fedora Silverblue (secureblue image)
# Purpose  : Logging, dry-run handling, idempotency markers, guards

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

SCRIPT_VERSION="0.1.0"
LOG_FILE="${LOG_FILE:-/var/log/secure_oss.log}"
MARKER_DIR="/etc/secure_oss/applied"
SENTINEL_REBOOT="/etc/secure_oss/pending-reboot"
DRY_RUN="${DRY_RUN:-0}"
_FAILED=0   # set to 1 by any non-fatal section failure; checked at script end

# ---------------------------------------------------------------------------
# Colour (only when stdout is a terminal)
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    _RED='\033[0;31m'
    _YELLOW='\033[1;33m'
    _GREEN='\033[0;32m'
    _CYAN='\033[0;36m'
    _BOLD='\033[1m'
    _RESET='\033[0m'
else
    _RED='' _YELLOW='' _GREEN='' _CYAN='' _BOLD='' _RESET=''
fi

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo -e "${_GREEN}${msg}${_RESET}"
    echo "${msg}" >> "${LOG_FILE}" 2>/dev/null || true
}

warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $*"
    echo -e "${_YELLOW}${msg}${_RESET}" >&2
    echo "${msg}" >> "${LOG_FILE}" 2>/dev/null || true
}

die() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] FATAL: $*"
    echo -e "${_RED}${msg}${_RESET}" >&2
    echo "${msg}" >> "${LOG_FILE}" 2>/dev/null || true
    exit 1
}

banner() {
    echo -e "${_BOLD}${_CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    printf "║  %-52s  ║\n" "$*"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${_RESET}"
}

reboot_notice() {
    echo -e "${_BOLD}${_YELLOW}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  REBOOT REQUIRED                                     ║"
    printf "║  %-52s  ║\n" "$*"
    echo "║  Run: systemctl reboot                               ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${_RESET}"
}

# ---------------------------------------------------------------------------
# Dry-run wrapper
# All state-changing operations must go through run_cmd() or write_file().
# ---------------------------------------------------------------------------

run_cmd() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "${_CYAN}[DRY RUN] Would run: $*${_RESET}"
    else
        log "Running: $*"
        eval "$@"
    fi
}

# write_file PATH CONTENT
# Writes CONTENT to PATH, respecting dry-run mode.
# Usage: write_file /path/to/file "$(cat <<'EOF'
# ...content...
# EOF
# )"
write_file() {
    local path="$1"
    local content="$2"
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "${_CYAN}[DRY RUN] Would write: ${path}${_RESET}"
        echo -e "${_CYAN}--- content ---${_RESET}"
        echo "${content}"
        echo -e "${_CYAN}---------------${_RESET}"
    else
        log "Writing: ${path}"
        mkdir --parents "$(dirname "${path}")"
        echo "${content}" > "${path}"
        restorecon -v "${path}" 2>/dev/null || true
    fi
}

# append_block PATH BEGIN_MARKER END_MARKER CONTENT
# Replaces any existing block between the markers, or appends a new one.
# Idempotent: re-running updates the block with fresh content.
append_block() {
    local path="$1"
    local begin_marker="$2"
    local end_marker="$3"
    local content="$4"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "${_CYAN}[DRY RUN] Would update block '${begin_marker}' in ${path}${_RESET}"
        return 0
    fi

    log "Updating block '${begin_marker}' in ${path}"

    # Remove existing block if present, then append fresh content
    python3 - "${path}" "${begin_marker}" "${end_marker}" "${content}" <<'PYEOF'
import sys, os

path       = sys.argv[1]
begin_mark = sys.argv[2]
end_mark   = sys.argv[3]
content    = sys.argv[4]

if os.path.exists(path):
    with open(path, 'r') as fh:
        lines = fh.readlines()
    # Strip existing block
    filtered = []
    inside = False
    for line in lines:
        if begin_mark in line:
            inside = True
        if not inside:
            filtered.append(line)
        if end_mark in line:
            inside = False
    # Ensure trailing newline before our block
    text = ''.join(filtered).rstrip('\n') + '\n'
else:
    text = ''

new_block = f"\n{begin_mark}\n{content}\n{end_mark}\n"
text += new_block

with open(path, 'w') as fh:
    fh.write(text)
PYEOF

    restorecon -v "${path}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Prerequisite guards
# ---------------------------------------------------------------------------

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This script must be run as root (use: sudo bash $0)"
    fi
}

is_silverblue() {
    # Returns 0 (true) if running on any Fedora Atomic/ostree desktop variant
    if ! command -v rpm-ostree &>/dev/null; then
        return 1
    fi
    if ! grep --quiet --ignore-case "fedora" /etc/os-release 2>/dev/null; then
        return 1
    fi
    return 0
}

is_secureblue() {
    # Returns 0 (true) if the active ostree deployment is a secureblue image
    if ! command -v rpm-ostree &>/dev/null; then
        return 1
    fi
    rpm-ostree status 2>/dev/null | grep --quiet "secureblue"
}

require_secureblue() {
    if ! is_secureblue; then
        die "This script requires a secureblue image to be the active deployment.
Run provision.sh first and reboot, then re-run this script."
    fi
}

require_silverblue() {
    if ! is_silverblue; then
        die "This script must be run on Fedora Silverblue (or another Fedora Atomic variant)."
    fi
}

# ---------------------------------------------------------------------------
# Reboot sentinel
# ---------------------------------------------------------------------------

set_reboot_pending() {
    local reason="${1:-unspecified}"
    mkdir --parents "$(dirname "${SENTINEL_REBOOT}")"
    echo "${reason}" > "${SENTINEL_REBOOT}"
}

check_reboot_pending() {
    if [[ -f "${SENTINEL_REBOOT}" ]]; then
        local reason
        reason="$(cat "${SENTINEL_REBOOT}")"
        reboot_notice "${reason}"
        die "Cannot continue until system is rebooted. Reason: ${reason}"
    fi
}

clear_reboot_pending() {
    rm --force "${SENTINEL_REBOOT}"
}

# ---------------------------------------------------------------------------
# Idempotency markers
# ---------------------------------------------------------------------------

is_applied() {
    # Returns 0 (true) if step $1 has already been marked as applied
    local step="$1"
    [[ -f "${MARKER_DIR}/${step}" ]]
}

mark_applied() {
    local step="$1"
    if [[ "${DRY_RUN}" != "1" ]]; then
        mkdir --parents "${MARKER_DIR}"
        echo "$(date '+%Y-%m-%d %H:%M:%S')" > "${MARKER_DIR}/${step}"
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing helper
# Call parse_common_args "$@" from each script's main()
# Sets DRY_RUN=1 if --dry-run is present.
# Returns remaining args in REMAINING_ARGS array.
# ---------------------------------------------------------------------------

parse_common_args() {
    REMAINING_ARGS=()
    for arg in "$@"; do
        case "${arg}" in
            --dry-run)
                DRY_RUN=1
                warn "Dry-run mode enabled — no changes will be made."
                ;;
            --help|-h)
                # Callers should define usage() before calling parse_common_args
                if declare -f usage &>/dev/null; then
                    usage
                fi
                exit 0
                ;;
            *)
                REMAINING_ARGS+=("${arg}")
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# SSH session detection
# Warn before operations that will briefly drop network (NM restart, etc.)
# ---------------------------------------------------------------------------

is_ssh_session() {
    [[ -n "${SSH_CLIENT:-}" ]] || [[ -n "${SSH_TTY:-}" ]]
}

warn_if_ssh_will_disconnect() {
    if is_ssh_session; then
        warn "You are connected via SSH. The next operation will restart NetworkManager,"
        warn "which will briefly drop your connection. If the session dies, reconnect and re-run."
        warn "Press Ctrl+C within 5 seconds to abort."
        sleep 5
    fi
}
