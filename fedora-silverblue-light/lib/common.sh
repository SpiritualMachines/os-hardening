#!/usr/bin/env bash
# lib/common.sh — Shared utilities for secure_oss Silverblue-light scripts
# Sourced by harden.sh; not executed directly.
#
# Platform : Fedora Silverblue (vanilla — no secureblue rebase required)
# Purpose  : Logging, dry-run handling, idempotency markers, guards

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

SCRIPT_VERSION="0.1.0"
LOG_FILE="${LOG_FILE:-/var/log/secure_oss_light.log}"
MARKER_DIR="/etc/secure_oss_light/applied"
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

# ---------------------------------------------------------------------------
# Prerequisite guards
# ---------------------------------------------------------------------------

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This script must be run as root (use: sudo bash $0)"
    fi
}

require_silverblue() {
    if ! command -v rpm-ostree &>/dev/null; then
        die "rpm-ostree not found. This script must be run on Fedora Silverblue (or another Fedora Atomic variant)."
    fi
    if ! grep --quiet --ignore-case "fedora" /etc/os-release 2>/dev/null; then
        die "This script must be run on Fedora Silverblue (or another Fedora Atomic variant)."
    fi
}

# ---------------------------------------------------------------------------
# Idempotency markers
# ---------------------------------------------------------------------------

is_applied() {
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
