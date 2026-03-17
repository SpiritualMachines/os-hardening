#!/usr/bin/env bash
# provision.sh — Install security packages on Ubuntu Desktop
#
# Platform  : Ubuntu Desktop 22.04 LTS / 24.04 LTS (GNOME)
# Purpose   : Install packages required by harden.sh and remove Ubuntu telemetry,
#             crash reporting, and noise packages. Safe to run immediately after
#             OS installation.
# Tested on : Ubuntu Desktop 22.04 LTS, Ubuntu Desktop 24.04 LTS
# Requires  : root, internet access
#
# Usage:
#   sudo bash provision.sh [--dry-run] [--remove-snap] [--keep-ubuntu-pro]
#
# After this script completes, run:
#   sudo bash harden.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

REMOVE_SNAP=0
KEEP_UBUNTU_PRO=0

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash provision.sh [OPTIONS]

Install security packages and remove telemetry on Ubuntu Desktop.

Options:
  --remove-snap       Remove snapd and all snap packages.
                      WARNING: Ubuntu Desktop ships Firefox as a snap by default.
                      Removing snapd will also remove Firefox unless you install
                      the Mozilla PPA deb package first. See INSTRUCTIONS.md.
  --keep-ubuntu-pro   Do not remove ubuntu-advantage-tools / ubuntu-pro-client
  --dry-run           Show what would be done without making changes
  --help              Show this help

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
            --remove-snap)
                REMOVE_SNAP=1
                shift
                ;;
            --keep-ubuntu-pro)
                KEEP_UBUNTU_PRO=1
                shift
                ;;
            *)
                die "Unknown argument: $1. Run with --help for usage."
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Section 1: Update apt cache
# ---------------------------------------------------------------------------

update_apt() {
    log "Updating apt package cache..."
    run_cmd apt-get update --quiet
}

# ---------------------------------------------------------------------------
# Section 2: Install security packages
#
# auditd              Linux Audit daemon — records security-relevant kernel events
#                     (file access, syscalls, privilege escalation) to a tamper-
#                     evident log.
#
# audispd-plugins     Plugins for auditd event dispatch (remote logging, etc.)
#
# libpam-pwquality    PAM module enforcing password complexity/length rules.
#                     Prevents weak passwords on local accounts.
#
# unattended-upgrades Automatically installs security updates. Essential even on
#                     desktop systems — users rarely patch manually on schedule.
#
# apt-listchanges     Shows changelogs before applying updates; integrates with
#                     unattended-upgrades for mail notification of changes.
#
# apparmor-utils      Utilities for managing AppArmor profiles (aa-status, aa-enforce,
#                     aa-complain). AppArmor itself is pre-installed on Ubuntu.
#
# ufw                 Uncomplicated Firewall — a user-friendly frontend for
#                     iptables/nftables. Pre-installed on many Ubuntu images.
#
# dconf-cli           Command-line tool for reading and writing dconf keys.
#                     Required by harden.sh to apply system-level GNOME policy
#                     (dconf update) and verify GNOME settings.
# ---------------------------------------------------------------------------

install_packages() {
    local packages=(
        auditd
        audispd-plugins
        libpam-pwquality
        unattended-upgrades
        apt-listchanges
        apparmor-utils
        ufw
        dconf-cli
    )

    log "Installing security packages: ${packages[*]}"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would run: apt-get install -y ${packages[*]}"
        return 0
    fi

    DEBIAN_FRONTEND=noninteractive apt-get install \
        --yes \
        --quiet \
        --no-install-recommends \
        "${packages[@]}"

    log "Security packages installed."
}

# ---------------------------------------------------------------------------
# Section 3: Remove telemetry and noise packages
#
# apport              Ubuntu crash handler / bug reporter. Intercepts crashes,
#                     collects potentially sensitive process memory contents,
#                     and offers to submit reports to Canonical/Launchpad.
#
# apport-symptoms     Helper scripts used by apport to diagnose common issues.
#                     Removed together with apport.
#
# whoopsie            Ubuntu's crash submission daemon. Sends crash reports to
#                     errors.ubuntu.com in the background without user interaction.
#
# kerneloops          Collects and submits kernel oops reports to kerneloops.org.
#                     Pure telemetry — not needed on end-user systems.
#
# ubuntu-report       Ubuntu system information reporter. Sends hardware and
#                     software configuration data to Canonical on first boot.
#
# popularity-contest  Periodically reports which packages are installed/used to
#                     Canonical. Pure telemetry — no user benefit.
#
# ubuntu-advantage-tools / ubuntu-pro-client
#                     The Ubuntu Pro subscription client. Phones home to
#                     Canonical's contract servers on a schedule to check
#                     subscription status, even when no subscription is active.
#                     Also enables esm-infra, livepatch, and other services
#                     that may not be desired. Remove unless you use Ubuntu Pro.
#
# snapd               Snap package manager. Downloads packages from Canonical's
#                     servers with automatic background refreshes and phoning home
#                     for snap metrics. Creates loopback devices for each snap.
#
#                     !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#                     WARNING: Ubuntu Desktop ships Firefox as a snap by default.
#                     Removing snapd WILL REMOVE Firefox and GNOME Software.
#                     Before passing --remove-snap you MUST either:
#                       a) Install the Mozilla PPA Firefox deb first:
#                          add-apt-repository ppa:mozillateam/ppa
#                          apt-get install -t 'o=LP-PPA-mozillateam' firefox
#                       b) Install another browser (chromium, brave, etc.)
#                     snapd removal is NOT the default for this reason.
#                     !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# ---------------------------------------------------------------------------

remove_telemetry_packages() {
    local packages_to_remove=(
        apport
        apport-symptoms
        whoopsie
        kerneloops
        ubuntu-report
        popularity-contest
    )

    if [[ "${KEEP_UBUNTU_PRO}" -eq 0 ]]; then
        packages_to_remove+=(
            ubuntu-advantage-tools
            ubuntu-pro-client
        )
    else
        warn "Keeping ubuntu-advantage-tools / ubuntu-pro-client (--keep-ubuntu-pro)"
    fi

    if [[ "${REMOVE_SNAP}" -eq 1 ]]; then
        warn "==========================================================="
        warn "  --remove-snap specified. This WILL remove Firefox and"
        warn "  gnome-software if they are installed as snaps."
        warn "  Ensure you have a replacement browser installed first."
        warn "==========================================================="
        packages_to_remove+=(snapd)
    else
        log "Keeping snapd (pass --remove-snap to remove; see usage for Firefox warning)"
    fi

    log "Removing telemetry packages: ${packages_to_remove[*]}"

    local actually_installed=()
    for pkg in "${packages_to_remove[@]}"; do
        if dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep --quiet "install ok installed"; then
            actually_installed+=("${pkg}")
        else
            log "  ${pkg} — not installed, skipping"
        fi
    done

    if [[ "${#actually_installed[@]}" -eq 0 ]]; then
        log "No targeted telemetry packages found — nothing to remove."
        return 0
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would run: apt-get purge --yes ${actually_installed[*]}"
        echo "[DRY RUN] Would run: apt-get autoremove --yes"
        return 0
    fi

    DEBIAN_FRONTEND=noninteractive apt-get purge \
        --yes \
        "${actually_installed[@]}"

    apt-get autoremove --yes --quiet

    # If snapd was removed, clean up leftover mount points and snap directories
    if [[ "${REMOVE_SNAP}" -eq 1 ]]; then
        _cleanup_snap_leftovers
    fi

    log "Telemetry packages removed."
}

_cleanup_snap_leftovers() {
    log "Cleaning up snapd leftovers..."

    # Remove snap mount points (loopback devices are gone after purge + reboot,
    # but the mount dirs may linger)
    if [[ -d /snap ]]; then
        rm --recursive --force /snap
        log "Removed /snap directory"
    fi

    # Remove snap data directories
    if [[ -d /var/snap ]]; then
        rm --recursive --force /var/snap
        log "Removed /var/snap directory"
    fi

    if [[ -d /var/lib/snapd ]]; then
        rm --recursive --force /var/lib/snapd
        log "Removed /var/lib/snapd directory"
    fi

    # Prevent snapd from being reinstalled as a dependency.
    # On Ubuntu Desktop, gnome-software and ubuntu-desktop depend on snapd.
    # This pin prevents apt from pulling it back in automatically.
    cat > /etc/apt/preferences.d/no-snapd <<'EOF'
# secure_oss: prevent snapd from being reinstalled
Package: snapd
Pin: release a=*
Pin-Priority: -1
EOF
    log "Pinned snapd to priority -1 (will not be reinstalled automatically)"
}

# ---------------------------------------------------------------------------
# Section 4: Enable and start services installed in Section 2
# ---------------------------------------------------------------------------

enable_services() {
    local services_to_enable=(
        auditd
    )

    for svc in "${services_to_enable[@]}"; do
        if ! systemctl cat "${svc}.service" &>/dev/null; then
            warn "${svc}.service unit not found — skipping enable"
            continue
        fi
        if systemctl is-enabled "${svc}.service" &>/dev/null; then
            log "${svc} already enabled"
        else
            log "Enabling and starting ${svc}"
            run_cmd systemctl enable --now "${svc}.service"
        fi
    done
}

# ---------------------------------------------------------------------------
# Section 5: Pre-configure unattended-upgrades
#
# We do a basic enable here so the service starts. harden.sh will write the
# full configuration including notification email and origin patterns.
# ---------------------------------------------------------------------------

enable_unattended_upgrades() {
    if is_applied "unattended-upgrades-enabled"; then
        log "unattended-upgrades already enabled — skipping"
        return 0
    fi

    log "Enabling unattended-upgrades via dpkg-reconfigure"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would run: dpkg-reconfigure -plow unattended-upgrades"
        return 0
    fi

    # dpkg-reconfigure with DEBIAN_FRONTEND=noninteractive auto-answers "yes"
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure \
        --priority=low \
        unattended-upgrades

    mark_applied "unattended-upgrades-enabled"
    log "unattended-upgrades enabled. Configure email/behavior in harden.sh."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    mkdir --parents /var/log
    log "=== secure_oss Ubuntu Desktop provision.sh v${SCRIPT_VERSION} ==="

    require_root
    require_ubuntu
    require_internet

    banner "Updating apt cache"
    update_apt

    banner "Installing security packages"
    install_packages

    banner "Removing telemetry packages"
    remove_telemetry_packages

    banner "Enabling security services"
    enable_services

    banner "Enabling unattended-upgrades"
    enable_unattended_upgrades

    echo ""
    log "=== provision.sh complete ==="
    log ""
    log "Next step: sudo bash ${SCRIPT_DIR}/harden.sh"
    log "  Options: --skip SECTIONS  --mask-cups  --dry-run"
    echo ""
}

main "$@"
