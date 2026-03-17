#!/usr/bin/env bash
# lib/common.sh — Shared utilities for secure_oss Ubuntu Desktop scripts
# Sourced by provision.sh and harden.sh; not executed directly.
#
# Platform : Ubuntu Desktop (22.04 LTS / 24.04 LTS)
# Purpose  : Logging, dry-run handling, idempotency markers, guards,
#            desktop-environment detection, and sudo-user resolution

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

require_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot detect OS. /etc/os-release not found."
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
        die "This script requires Ubuntu. Detected: ${PRETTY_NAME:-unknown}"
    fi
    log "Detected: ${PRETTY_NAME}"
}

require_package() {
    # Fail loudly if a package required by harden.sh is not installed.
    local pkg="$1"
    if ! dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep --quiet "install ok installed"; then
        die "Required package '${pkg}' is not installed. Run provision.sh first."
    fi
}

require_internet() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        return 0
    fi
    if ! curl --silent --max-time 5 --head https://archive.ubuntu.com &>/dev/null; then
        die "No internet access detected. Ensure network connectivity before running provision.sh."
    fi
}

# ---------------------------------------------------------------------------
# Desktop environment detection
# Ubuntu Desktop ships GNOME as its only supported desktop. We check via dpkg
# rather than rpm (not available on Ubuntu). Sets DE to "gnome" or "unknown".
# ---------------------------------------------------------------------------

DE=""

detect_desktop_environment() {
    # Try environment variables first (reliable when run via sudo from a session)
    local xdg="${XDG_CURRENT_DESKTOP:-}"
    local session="${DESKTOP_SESSION:-}"

    if [[ "${xdg}" =~ [Gg][Nn][Oo][Mm][Ee] ]] || [[ "${session}" =~ gnome ]]; then
        DE="gnome"
    else
        # Fall back to installed package detection via dpkg.
        # gnome-shell is the core package for GNOME on Ubuntu Desktop.
        if dpkg-query -W -f='${Status}' gnome-shell 2>/dev/null | grep --quiet "install ok installed"; then
            DE="gnome"
        else
            DE="unknown"
            warn "Could not detect desktop environment."
            warn "gnome-shell does not appear to be installed."
            warn "GNOME-specific hardening will be skipped."
            warn "Set XDG_CURRENT_DESKTOP=GNOME and re-run if needed."
        fi
    fi

    log "Detected desktop environment: ${DE}"
}

# ---------------------------------------------------------------------------
# Sudo user resolution
# When running as root via sudo, gets the original calling user for
# applying user-level DE settings (gsettings, dconf, etc.)
# ---------------------------------------------------------------------------

get_sudo_user() {
    local user="${SUDO_USER:-}"
    if [[ -z "${user}" ]] || [[ "${user}" == "root" ]]; then
        # Script was run directly as root — try logname
        user="$(logname 2>/dev/null || echo "")"
    fi
    if [[ -z "${user}" ]] || ! id "${user}" &>/dev/null; then
        warn "Could not determine the calling user for DE settings."
        warn "User-level settings will be skipped. Re-run with sudo from your desktop session."
        echo ""
        return 1
    fi
    echo "${user}"
}

run_as_user() {
    # Run a command as the desktop user. Usage: run_as_user USERNAME CMD [ARGS...]
    local user="$1"
    shift
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "${_CYAN}[DRY RUN] Would run as ${user}: $*${_RESET}"
    else
        log "Running as ${user}: $*"
        sudo --user="${user}" --preserve-env=HOME,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS "$@"
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
