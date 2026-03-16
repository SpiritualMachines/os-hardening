#!/usr/bin/env bash
# lib/common.sh — Shared utilities for secure_oss Fedora scripts
# Sourced by provision.sh and harden.sh; not executed directly.
#
# Platform : Fedora Workstation (GNOME) / Fedora KDE Plasma
# Purpose  : Logging, dry-run handling, idempotency markers, guards

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

SCRIPT_VERSION="0.1.0"
LOG_FILE="${LOG_FILE:-/var/log/secure_oss.log}"
MARKER_DIR="/etc/secure_oss/applied"
DRY_RUN="${DRY_RUN:-0}"
_FAILED=0

# ---------------------------------------------------------------------------
# Colour
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    _RED='\033[0;31m'; _YELLOW='\033[1;33m'; _GREEN='\033[0;32m'
    _CYAN='\033[0;36m'; _BOLD='\033[1m'; _RESET='\033[0m'
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
# Dry-run wrappers
# ---------------------------------------------------------------------------

run_cmd() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "${_CYAN}[DRY RUN] Would run: $*${_RESET}"
    else
        log "Running: $*"
        eval "$@"
    fi
}

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
path, begin_mark, end_mark, content = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
if os.path.exists(path):
    with open(path, 'r') as fh:
        lines = fh.readlines()
    filtered, inside = [], False
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
text += f"\n{begin_mark}\n{content}\n{end_mark}\n"
with open(path, 'w') as fh:
    fh.write(text)
PYEOF

    restorecon -v "${path}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "This script must be run as root (use: sudo bash $0)"
}

require_fedora() {
    if ! grep --quiet --ignore-case "fedora" /etc/os-release 2>/dev/null; then
        die "This script must be run on Fedora."
    fi
    # Reject Silverblue/Atomic variants — those have their own scripts
    if command -v rpm-ostree &>/dev/null && rpm-ostree status &>/dev/null 2>&1; then
        die "This is an ostree/Atomic system. Use the fedora-silverblue scripts instead."
    fi
}

# ---------------------------------------------------------------------------
# Desktop environment detection
# Sets the global DE variable to "gnome", "kde", or "unknown"
# ---------------------------------------------------------------------------

DE=""

detect_desktop_environment() {
    # Try environment variables first (reliable when run via sudo from a session)
    local xdg="${XDG_CURRENT_DESKTOP:-}"
    local session="${DESKTOP_SESSION:-}"

    if [[ "${xdg}" =~ [Gg][Nn][Oo][Mm][Ee] ]] || [[ "${session}" =~ gnome ]]; then
        DE="gnome"
    elif [[ "${xdg}" =~ [Kk][Dd][Ee] ]] || [[ "${session}" =~ plasma|kde ]]; then
        DE="kde"
    else
        # Fall back to installed package detection
        if rpm --query gnome-shell &>/dev/null 2>&1; then
            DE="gnome"
        elif rpm --query plasma-desktop &>/dev/null 2>&1; then
            DE="kde"
        else
            DE="unknown"
            warn "Could not detect desktop environment — DE-specific hardening will be skipped."
            warn "Set XDG_CURRENT_DESKTOP=GNOME or XDG_CURRENT_DESKTOP=KDE and re-run if needed."
        fi
    fi

    log "Detected desktop environment: ${DE}"
}

# ---------------------------------------------------------------------------
# Sudo user resolution
# When running as root via sudo, gets the original calling user for
# applying user-level DE settings (gsettings, kwriteconfig5, etc.)
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
    [[ -f "${MARKER_DIR}/${1}" ]]
}

mark_applied() {
    if [[ "${DRY_RUN}" != "1" ]]; then
        mkdir --parents "${MARKER_DIR}"
        echo "$(date '+%Y-%m-%d %H:%M:%S')" > "${MARKER_DIR}/${1}"
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
# Argument parsing
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
                declare -f usage &>/dev/null && usage
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
        warn "SSH session detected. Next operation will restart NetworkManager."
        warn "Press Ctrl+C within 5 seconds to abort."
        sleep 5
    fi
}
