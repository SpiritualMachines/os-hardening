#!/usr/bin/env bash
# lib/common.sh — Shared utilities for secure_oss macOS scripts
# Sourced by provision.sh and harden.sh; not executed directly.
#
# Platform : macOS 13 (Ventura) / 14 (Sonoma) / 15 (Sequoia)
# Purpose  : Logging, dry-run handling, idempotency markers, guards,
#            console-user resolution, and sudo-user helpers

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

SCRIPT_VERSION="0.1.0"
LOG_FILE="${LOG_FILE:-/var/log/secure_oss.log}"
MARKER_DIR="/etc/secure_oss/applied"
DRY_RUN="${DRY_RUN:-0}"
_FAILED=0   # set to 1 by any non-fatal section failure; checked at script end

# Global: sections to skip, populated by --skip argument in harden.sh
SKIP_SECTIONS=()

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
    echo "║  REBOOT RECOMMENDED                                  ║"
    printf "║  %-52s  ║\n" "$*"
    echo "║  Run: sudo reboot                                    ║"
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
        # Use -p (BSD mkdir) rather than --parents (GNU mkdir)
        mkdir -p "$(dirname "${path}")"
        echo "${content}" > "${path}"
        # NOTE: restorecon is NOT called here — macOS has no SELinux.
    fi
}

# append_block PATH BEGIN_MARKER END_MARKER CONTENT
# Replaces any existing block between the markers, or appends a new one.
# Idempotent: re-running updates the block with fresh content.
# Requires Python 3 (available via Xcode Command Line Tools or system Python).
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

    python3 - "${path}" "${begin_marker}" "${end_marker}" "${content}" <<'PYEOF'
import sys, os

path       = sys.argv[1]
begin_mark = sys.argv[2]
end_mark   = sys.argv[3]
content    = sys.argv[4]

if os.path.exists(path):
    with open(path, 'r') as fh:
        lines = fh.readlines()
    filtered = []
    inside = False
    for line in lines:
        if begin_mark in line:
            inside = True
        if not inside:
            filtered.append(line)
        if end_mark in line:
            inside = False
    text = ''.join(filtered).rstrip('\n') + '\n'
else:
    text = ''

new_block = f"\n{begin_mark}\n{content}\n{end_mark}\n"
text += new_block

with open(path, 'w') as fh:
    fh.write(text)
PYEOF
}

# ---------------------------------------------------------------------------
# Prerequisite guards
# ---------------------------------------------------------------------------

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This script must be run as root (use: sudo bash $0)"
    fi
}

require_macos() {
    if [[ "$(uname -s)" != "Darwin" ]]; then
        die "This script requires macOS."
    fi
    local ver
    ver=$(sw_vers -productVersion)
    log "Detected: macOS ${ver}"
}

require_min_macos_version() {
    # Usage: require_min_macos_version MAJOR_VERSION
    # Exits if the running macOS major version is below the required minimum.
    local required_major="$1"
    local ver
    ver=$(sw_vers -productVersion)
    local major
    major=$(echo "${ver}" | cut -d. -f1)
    if [[ "${major}" -lt "${required_major}" ]]; then
        die "macOS ${required_major} or later is required. Detected: ${ver}"
    fi
}

require_internet() {
    [[ "${DRY_RUN}" == "1" ]] && return 0
    if ! curl --silent --max-time 5 --head https://www.apple.com &>/dev/null; then
        die "No internet access detected. Ensure network connectivity before running this script."
    fi
}

# ---------------------------------------------------------------------------
# macOS version helpers
# ---------------------------------------------------------------------------

get_macos_major_version() {
    # Returns the integer major version (e.g. 13, 14, 15)
    sw_vers -productVersion | cut -d. -f1
}

# ---------------------------------------------------------------------------
# Console user resolution
# When running as root via sudo, gets the user logged into the GUI console.
# Used for applying user-level defaults(1) settings (Siri, Spotlight, etc.)
# ---------------------------------------------------------------------------

get_console_user() {
    # Get the user logged into the GUI console (not root).
    # stat -f "%Su" /dev/console is the canonical macOS way to find the
    # logged-in GUI user even when running as root under sudo.
    local user
    user=$(stat -f "%Su" /dev/console 2>/dev/null || echo "")
    if [[ -z "${user}" ]] || [[ "${user}" == "root" ]]; then
        # Fall back to the SUDO_USER variable (set when sudo is invoked)
        user="${SUDO_USER:-}"
    fi
    if [[ -z "${user}" ]] || ! id "${user}" &>/dev/null; then
        warn "Could not determine the console user for user-level settings."
        warn "Re-run with sudo from a desktop session if needed."
        echo ""
        return 1
    fi
    echo "${user}"
}

get_console_user_uid() {
    # Returns the numeric UID of the console user, or empty string on failure.
    local user
    user=$(get_console_user) || { echo ""; return 1; }
    id -u "${user}"
}

run_as_user() {
    # Run a command as the desktop/console user.
    # Usage: run_as_user USERNAME CMD [ARGS...]
    local user="$1"
    shift
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "${_CYAN}[DRY RUN] Would run as ${user}: $*${_RESET}"
    else
        log "Running as ${user}: $*"
        sudo --user="${user}" "$@"
    fi
}

# ---------------------------------------------------------------------------
# DNS cache flush (macOS-specific)
# ---------------------------------------------------------------------------

flush_dns_cache() {
    log "Flushing DNS cache..."
    run_cmd dscacheutil -flushcache
    # mDNSResponder handles both mDNS and standard DNS caching on macOS.
    # SIGHUP triggers a cache flush without restarting the daemon.
    run_cmd killall -HUP mDNSResponder 2>/dev/null || true
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
        mkdir -p "${MARKER_DIR}"
        echo "$(date '+%Y-%m-%d %H:%M:%S')" > "${MARKER_DIR}/${step}"
    fi
}

# ---------------------------------------------------------------------------
# Section runner — per-section failure isolation
# ---------------------------------------------------------------------------

run_section() {
    local name="$1"
    local fn="$2"
    if should_skip "${name}"; then
        warn "Skipping section: ${name} (--skip requested)"
        return 0
    fi
    banner "${name}"
    if "${fn}"; then
        log "Section '${name}' completed."
    else
        warn "Section '${name}' encountered an error. Continuing."
        _FAILED=1
    fi
}

should_skip() {
    local section="$1"
    for s in "${SKIP_SECTIONS[@]+"${SKIP_SECTIONS[@]}"}"; do
        [[ "${s}" == "${section}" ]] && return 0
    done
    return 1
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
