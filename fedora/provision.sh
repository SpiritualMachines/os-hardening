#!/usr/bin/env bash
# provision.sh — Package provisioning for Fedora Workstation / KDE Plasma
#
# Platform  : Fedora Workstation (GNOME) or Fedora KDE Plasma (mutable)
# Purpose   : Hardens DNF configuration, performs a full system update,
#             installs security tooling, removes telemetry/unnecessary packages,
#             and enables automatic security updates.
# Tested on : Fedora 41 Workstation, Fedora 41 KDE Plasma
# Requires  : root, internet access
#
# Usage:
#   sudo bash provision.sh [--dry-run] [--skip-update]
#
# Run harden.sh after this script completes. A reboot is recommended
# (but not required) before running harden.sh to pick up any kernel updates.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SKIP_UPDATE=0

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash provision.sh [OPTIONS]

Harden DNF, update the system, and install/remove packages for Fedora.

Options:
  --skip-update   Skip the full system update (faster for re-runs)
  --dry-run       Show what would be done without making changes
  --help          Show this help

Run harden.sh after this script completes.
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_args() {
    parse_common_args "$@"
    set -- "${REMAINING_ARGS[@]+"${REMAINING_ARGS[@]}"}"
    for arg in "$@"; do
        [[ "${arg}" == "--skip-update" ]] && SKIP_UPDATE=1
    done
}

# ---------------------------------------------------------------------------
# DNF configuration hardening
#
# gpgcheck=1 is already the Fedora default, but we set it explicitly and add
# localpkg_gpgcheck to prevent unsigned local RPMs from being installed.
# best=True ensures dependency resolution prefers the latest available versions.
# ---------------------------------------------------------------------------

harden_dnf_config() {
    if is_applied "dnf-config"; then
        log "DNF config already hardened — skipping"
        return 0
    fi

    log "Hardening DNF configuration"

    local dnf_conf="/etc/dnf/dnf.conf"

    # Ensure gpgcheck is set for all repos (it is by default, but be explicit)
    if ! grep --quiet "^gpgcheck=1" "${dnf_conf}" 2>/dev/null; then
        run_cmd bash -c "echo 'gpgcheck=1' >> ${dnf_conf}"
    fi

    # Block installation of unsigned local RPM packages
    if ! grep --quiet "^localpkg_gpgcheck" "${dnf_conf}" 2>/dev/null; then
        run_cmd bash -c "echo 'localpkg_gpgcheck=1' >> ${dnf_conf}"
    fi

    # Remove dependencies that are no longer required when a package is removed
    if ! grep --quiet "^clean_requirements_on_remove" "${dnf_conf}" 2>/dev/null; then
        run_cmd bash -c "echo 'clean_requirements_on_remove=True' >> ${dnf_conf}"
    fi

    # Prefer latest package versions when resolving dependencies
    if ! grep --quiet "^best=" "${dnf_conf}" 2>/dev/null; then
        run_cmd bash -c "echo 'best=True' >> ${dnf_conf}"
    fi

    mark_applied "dnf-config"
}

# ---------------------------------------------------------------------------
# System update
# ---------------------------------------------------------------------------

system_update() {
    if [[ "${SKIP_UPDATE}" -eq 1 ]]; then
        warn "Skipping system update (--skip-update)"
        return 0
    fi

    log "Running full system update (this may take a while...)"
    run_cmd dnf upgrade --refresh --assumeyes
}

# ---------------------------------------------------------------------------
# Install security tools
# ---------------------------------------------------------------------------

install_security_packages() {
    if is_applied "install-packages"; then
        log "Security packages already installed — skipping"
        return 0
    fi

    log "Installing security tooling"

    local packages=(
        # USB device authorization daemon — blocks unknown USB devices
        usbguard
        usbguard-notifier

        # Linux audit framework — records security-relevant system events
        audit

        # File integrity monitoring — detects unauthorized file changes
        aide

        # WireGuard VPN tools — for the optional kill-switch script
        wireguard-tools

        # Automatic security updates
        dnf-automatic

        # nftables (should already be present, firewalld backend)
        nftables

        # chrony — more secure NTP client (likely already installed)
        chrony
    )

    run_cmd dnf install --assumeyes "${packages[@]}"

    mark_applied "install-packages"
}

# ---------------------------------------------------------------------------
# Remove telemetry and attack-surface packages
# ---------------------------------------------------------------------------

remove_unnecessary_packages() {
    if is_applied "remove-packages"; then
        log "Package removal already applied — skipping"
        return 0
    fi

    log "Removing telemetry and unnecessary packages"

    # Packages to remove. Each entry is checked for presence first so the
    # script does not fail if a package is already absent.
    local packages_to_remove=(
        # ABRT — Automatic Bug Reporting Tool. Sends crash data to Red Hat.
        # We mask the systemd units in harden.sh as belt-and-suspenders.
        "abrt"
        "abrt-libs"
        "abrt-addon-ccpp"
        "abrt-addon-kerneloops"
        "abrt-addon-python"
        "abrt-addon-vmcore"
        "abrt-cli"
        "abrt-dbus"
        "abrt-desktop"
        "abrt-gui"
        "abrt-gui-libs"
        "abrt-journal-core"
        "abrt-plugin-sosreport"
        "abrt-tui"
        "libreport"
        "libreport-fedora"
        "libreport-gtk"
        "libreport-web"

        # telnet — unencrypted remote login protocol
        "telnet"

        # rsh — unencrypted remote shell (legacy)
        "rsh"

        # ypbind / yptools — NIS (Yellow Pages) client, legacy directory service
        "ypbind"
        "yp-tools"

        # tftp-client — trivial FTP, unencrypted
        "tftp"

        # talk — legacy unencrypted chat protocol
        "talk"
    )

    local to_remove=()
    for pkg in "${packages_to_remove[@]}"; do
        if rpm --query "${pkg}" &>/dev/null; then
            to_remove+=("${pkg}")
        fi
    done

    if [[ "${#to_remove[@]}" -eq 0 ]]; then
        log "No packages to remove (all already absent)"
    else
        log "Removing: ${to_remove[*]}"
        run_cmd dnf remove --assumeyes "${to_remove[@]}"
    fi

    mark_applied "remove-packages"
}

# ---------------------------------------------------------------------------
# Configure automatic security updates
#
# dnf-automatic with apply_updates=yes will automatically download and
# install security updates. The timer runs daily.
# ---------------------------------------------------------------------------

configure_auto_updates() {
    if is_applied "auto-updates"; then
        log "Auto-updates already configured — skipping"
        return 0
    fi

    log "Configuring automatic security updates via dnf-automatic"

    local auto_conf="/etc/dnf/automatic.conf"

    if [[ ! -f "${auto_conf}" ]]; then
        warn "dnf-automatic config not found at ${auto_conf} — skipping auto-update config"
        return 0
    fi

    # Ensure only security upgrades are applied automatically
    if [[ "${DRY_RUN}" != "1" ]]; then
        # upgrade_type: security = only security updates; default = all updates
        sed --in-place 's/^upgrade_type\s*=.*/upgrade_type = security/' "${auto_conf}"
        # Enable automatic application of updates (not just download)
        sed --in-place 's/^apply_updates\s*=.*/apply_updates = yes/' "${auto_conf}"
        # Email notifications disabled by default (no MTA assumed)
        sed --in-place 's/^emit_via\s*=.*/emit_via = stdio/' "${auto_conf}"
    else
        echo "[DRY RUN] Would configure ${auto_conf}: upgrade_type=security, apply_updates=yes"
    fi

    # Enable the timer (runs once per day)
    run_cmd systemctl enable --now dnf-automatic.timer

    mark_applied "auto-updates"
}

# ---------------------------------------------------------------------------
# Enable and configure audit daemon
# ---------------------------------------------------------------------------

configure_auditd() {
    if is_applied "auditd"; then
        log "auditd already configured — skipping"
        return 0
    fi

    log "Enabling auditd"
    run_cmd systemctl enable --now auditd.service

    mark_applied "auditd"
}

# ---------------------------------------------------------------------------
# Initialize AIDE database
# ---------------------------------------------------------------------------

configure_aide() {
    if is_applied "aide"; then
        log "AIDE already initialized — skipping"
        return 0
    fi

    if ! command -v aide &>/dev/null; then
        warn "aide not found — skipping AIDE initialization"
        return 0
    fi

    log "Initializing AIDE file integrity database (this takes several minutes)..."
    log "The database is stored at /var/lib/aide/aide.db.gz"
    log "Run 'sudo aide --check' periodically to detect unauthorized changes."

    if [[ "${DRY_RUN}" != "1" ]]; then
        aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
        log "AIDE database initialized. Schedule regular checks with:"
        log "  sudo aide --check"
    else
        echo "[DRY RUN] Would run: aide --init"
    fi

    mark_applied "aide"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    mkdir --parents /var/log "${MARKER_DIR}"
    log "=== secure_oss provision.sh v${SCRIPT_VERSION} ==="

    require_root
    require_fedora

    harden_dnf_config
    system_update
    install_security_packages
    remove_unnecessary_packages
    configure_auto_updates
    configure_auditd
    configure_aide

    log ""
    log "Provisioning complete."
    reboot_notice "Reboot recommended before running harden.sh"
    log "After rebooting, run: sudo bash ${SCRIPT_DIR}/harden.sh"

    if [[ "${_FAILED}" -ne 0 ]]; then
        exit 1
    fi
}

main "$@"
