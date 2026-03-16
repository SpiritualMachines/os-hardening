#!/usr/bin/env bash
# provision.sh — Install security packages on FreeBSD
#
# Platform  : FreeBSD 13 / 14
# Purpose   : Bootstrap pkg, install security tools required by harden.sh,
#             and remove/disable unnecessary default packages.
# Tested on : FreeBSD 14.1-RELEASE
# Requires  : root, internet access
#
# Usage:
#   sudo bash provision.sh [--dry-run]
#
# After this script completes, run:
#   sudo bash harden.sh

set -euo pipefail

DRY_RUN=0
LOG_FILE="/var/log/secure_oss.log"

log()  { local m="[$(date '+%Y-%m-%d %H:%M:%S')] $*"; echo -e "\033[0;32m${m}\033[0m"; echo "${m}" >> "${LOG_FILE}" 2>/dev/null || true; }
warn() { local m="[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $*"; echo -e "\033[1;33m${m}\033[0m" >&2; echo "${m}" >> "${LOG_FILE}" 2>/dev/null || true; }
die()  { echo -e "\033[0;31m[$(date '+%Y-%m-%d %H:%M:%S')] FATAL: $*\033[0m" >&2; exit 1; }

banner() {
    echo -e "\033[1m\033[0;36m"
    echo "╔══════════════════════════════════════════════════════╗"
    printf "║  %-52s  ║\n" "$*"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "\033[0m"
}

run_cmd() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would run: $*\033[0m"
    else
        log "Running: $*"
        eval "$@"
    fi
}

for arg in "$@"; do
    case "${arg}" in
        --dry-run) DRY_RUN=1; warn "Dry-run mode." ;;
        --help|-h) echo "Usage: sudo bash provision.sh [--dry-run]"; exit 0 ;;
        *) die "Unknown argument: ${arg}" ;;
    esac
done

[[ "${EUID}" -ne 0 ]] && die "Must be run as root."

if ! uname -s | grep --quiet FreeBSD; then
    die "This script must be run on FreeBSD."
fi

# ---------------------------------------------------------------------------
# Step 1: Bootstrap / update pkg
# ---------------------------------------------------------------------------

banner "Bootstrap pkg"

if ! command -v pkg &>/dev/null || ! pkg -N 2>/dev/null; then
    log "Bootstrapping pkg..."
    run_cmd env ASSUME_ALWAYS_YES=yes pkg bootstrap
else
    log "pkg is already bootstrapped."
fi

run_cmd pkg update --quiet

# ---------------------------------------------------------------------------
# Step 2: Install security packages
#
# sudo         — Privilege escalation with audit trail. FreeBSD's default
#                'su' has no per-command logging; sudo fixes this.
#
# ca_root_nss  — Mozilla's trusted CA bundle. Required for TLS verification
#                by many tools. Often absent on minimal installs.
#
# openssl      — Up-to-date OpenSSL; the base system's LibreSSL may lag.
#
# audit        — BSM (Basic Security Module) audit daemon. Records syscall-
#                level security events. The FreeBSD equivalent of auditd.
#
# syslog-ng    — Enhanced syslog daemon with filtering and remote forwarding
#                capabilities. Replaces the default syslogd.
#
# nmap         — Network scanner; useful for verifying firewall rules and
#                checking what services are actually exposed. (Admin tool only.)
#
# portaudit / pkg audit
#               FreeBSD's pkg includes vulnerability scanning natively via
#               'pkg audit'. No extra package needed.
# ---------------------------------------------------------------------------

banner "Installing security packages"

PACKAGES=(
    sudo
    ca_root_nss
    openssl
)

log "Installing: ${PACKAGES[*]}"

if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[DRY RUN] Would run: pkg install --yes ${PACKAGES[*]}"
else
    env ASSUME_ALWAYS_YES=yes pkg install --quiet "${PACKAGES[@]}"
fi

# ---------------------------------------------------------------------------
# Step 3: Run pkg audit (check for known vulnerable installed packages)
# ---------------------------------------------------------------------------

banner "Checking installed packages for known vulnerabilities"

if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[DRY RUN] Would run: pkg audit -F"
else
    # Update the vulnerability database, then audit
    pkg audit -F 2>/dev/null || {
        warn "pkg audit found vulnerable packages (see output above)."
        warn "Review and update or remove affected packages before continuing."
    }
fi

# ---------------------------------------------------------------------------
# Step 4: Enable BSM audit daemon in rc.conf
#
# auditd records security-relevant system calls. We enable it here so
# harden.sh can configure its rules without needing to restart it separately.
# ---------------------------------------------------------------------------

banner "Enabling audit daemon"

_rc_conf_set() {
    local key="$1" value="$2"
    if grep --quiet "^${key}=" /etc/rc.conf 2>/dev/null; then
        log "  ${key} already set in /etc/rc.conf — skipping"
    else
        log "  Setting ${key}=${value} in /etc/rc.conf"
        run_cmd "echo '${key}=${value}' >> /etc/rc.conf"
    fi
}

_rc_conf_set 'auditd_enable' '"YES"'

if [[ "${DRY_RUN}" != "1" ]]; then
    service auditd start 2>/dev/null || warn "Could not start auditd — may already be running."
fi

# ---------------------------------------------------------------------------

log ""
log "=== provision.sh complete ==="
log "Next step: sudo bash harden.sh"
