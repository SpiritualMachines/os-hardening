#!/usr/bin/env bash
# harden.sh — Additional hardening layer on top of secureblue
#
# Platform  : Fedora Silverblue running the secureblue image
# Purpose   : Applies privacy defaults and anti-MDM controls that secureblue
#             does not cover out of the box. All changes are written to /etc
#             or applied via systemctl — no /usr writes (immutable base).
# Tested on : secureblue silverblue-main (Fedora 41 base)
# Requires  : root, active secureblue deployment (run provision.sh + reboot first)
#
# Usage:
#   sudo bash harden.sh [--dry-run] [--dns PROVIDER] [--skip SECTION]
#
# DNS providers (--dns):
#   quad9      Quad9 DoT — nonprofit, DNSSEC, no logging (default)
#   mullvad    Mullvad DoT — privacy-focused, Sweden
#   both       Quad9 primary, Mullvad secondary
#
# Skip sections (--skip, comma-separated):
#   dns, dhcp, mac, usbguard, mdm, telemetry, cockpit, abrt
#
# Sections applied:
#   1. Encrypted DNS enforcement (Quad9/Mullvad DoT via dnsconfd/unbound)
#   2. DHCP hostname suppression (prevents hostname leakage on LAN)
#   3. MAC address randomization (per-connection, stronger than secureblue default)
#   4. USBGuard auto-setup (generates policy from current devices, enables service)
#   5. MDM domain blocking (/etc/hosts null-routing of MDM infrastructure)
#   6. Telemetry domain blocking (/etc/hosts null-routing of telemetry endpoints)
#   7. Cockpit masking (web-based admin console — remote access surface)
#   8. ABRT masking (Automatic Bug Reporting Tool — crash data phone-home)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

DNS_PROVIDER="quad9"
SKIP_SECTIONS=()

# DoT resolver definitions
# Format: "IP|HOSTNAME|PORT"
QUAD9_DOT="9.9.9.9|dns.quad9.net|853"
QUAD9_DOT_SECONDARY="149.112.112.112|dns.quad9.net|853"
MULLVAD_DOT="194.242.2.2|dns.mullvad.net|853"

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash harden.sh [OPTIONS]

Apply privacy and anti-MDM hardening on top of a secureblue Silverblue system.

Options:
  --dns PROVIDER    DNS-over-TLS provider: quad9 | mullvad | both (default: quad9)
  --skip SECTIONS   Comma-separated list of sections to skip
                    Values: dns, dhcp, mac, usbguard, mdm, telemetry, cockpit, abrt
  --dry-run         Show what would be done without making changes
  --help            Show this help

Example:
  sudo bash harden.sh --dns both --skip abrt
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
            --dns)
                DNS_PROVIDER="${2:?--dns requires a value (quad9, mullvad, or both)}"
                shift 2
                ;;
            --skip)
                IFS=',' read -ra SKIP_SECTIONS <<< "${2:?--skip requires a value}"
                shift 2
                ;;
            *)
                die "Unknown argument: $1. Run with --help for usage."
                ;;
        esac
    done
}

should_skip() {
    local section="$1"
    for s in "${SKIP_SECTIONS[@]+"${SKIP_SECTIONS[@]}"}"; do
        [[ "${s}" == "${section}" ]] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Section runner — catches failures per-section without aborting everything
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
        log "Section '${name}' completed successfully."
    else
        warn "Section '${name}' encountered an error. Continuing with remaining sections."
        _FAILED=1
    fi
}

# ---------------------------------------------------------------------------
# Section 1: Encrypted DNS
#
# secureblue uses dnsconfd + unbound, with dns=dnsconfd set in NetworkManager.
# The ujust dns-selector is interactive — we replicate it non-interactively.
# We do NOT write directly to /etc/unbound/conf.d/ because dnsconfd manages
# unbound's runtime config and would overwrite us. We use dnsconfd CLI instead,
# falling back to unbound config if dnsconfd is not available.
# ---------------------------------------------------------------------------

configure_dns() {
    log "Configuring DNS-over-TLS provider: ${DNS_PROVIDER}"

    if is_applied "dns"; then
        log "DNS already configured — skipping (delete ${MARKER_DIR}/dns to re-apply)"
        return 0
    fi

    local resolvers=()
    case "${DNS_PROVIDER}" in
        quad9)
            resolvers=("${QUAD9_DOT}" "${QUAD9_DOT_SECONDARY}")
            ;;
        mullvad)
            resolvers=("${MULLVAD_DOT}")
            ;;
        both)
            resolvers=("${QUAD9_DOT}" "${MULLVAD_DOT}" "${QUAD9_DOT_SECONDARY}")
            ;;
        *)
            die "Unknown DNS provider: ${DNS_PROVIDER}. Use: quad9, mullvad, or both"
            ;;
    esac

    if command -v dnsconfd &>/dev/null; then
        log "dnsconfd is available — configuring via dnsconfd (secureblue native method)"
        _configure_dns_via_dnsconfd "${resolvers[@]}"
    else
        warn "dnsconfd not found — falling back to direct unbound configuration"
        _configure_dns_via_unbound "${resolvers[@]}"
    fi

    log "Verifying DNS resolution..."
    _verify_dns

    mark_applied "dns"
}

_configure_dns_via_dnsconfd() {
    local resolvers=("$@")

    # Build dnsconfd server arguments: each resolver as proto://IP#PORT
    local server_args=()
    for resolver in "${resolvers[@]}"; do
        local ip hostname port
        IFS='|' read -r ip hostname port <<< "${resolver}"
        server_args+=("tls://${ip}#${hostname}:${port}")
    done

    log "Setting dnsconfd resolvers: ${server_args[*]}"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would run: dnsconfd set-resolvers ${server_args[*]}"
        return 0
    fi

    # dnsconfd set-resolvers takes a JSON array or space-separated URIs
    # depending on the version — try the URI form first
    if dnsconfd set-resolvers "${server_args[@]}" 2>/dev/null; then
        log "dnsconfd resolvers set successfully"
    else
        warn "dnsconfd set-resolvers failed — attempting alternative approach"
        # Older dnsconfd versions may require a different invocation
        # Write a drop-in config for the dnsconfd service instead
        _configure_dns_via_dnsconfd_dropin "${resolvers[@]}"
    fi
}

_configure_dns_via_dnsconfd_dropin() {
    local resolvers=("$@")

    # Build a dnsconfd config override that pre-sets the upstream resolvers
    local conf_content="[main]"$'\n'
    conf_content+="# Configured by secure_oss harden.sh"$'\n'
    conf_content+="servers = "

    local server_list=()
    for resolver in "${resolvers[@]}"; do
        local ip hostname port
        IFS='|' read -r ip hostname port <<< "${resolver}"
        server_list+=("tls://${ip}#${hostname}:${port}")
    done
    conf_content+="${server_list[*]}"$'\n'

    write_file "/etc/dnsconfd.conf.d/10-secure-oss-dot.conf" "${conf_content}"
    run_cmd systemctl restart dnsconfd.service
}

_configure_dns_via_unbound() {
    local resolvers=("$@")

    # Build an unbound forward-zone config for DoT
    local conf_lines="# secure_oss: DNS-over-TLS upstream resolvers"
    conf_lines+=$'\n'"# Configured by harden.sh — do not edit manually"
    conf_lines+=$'\n'
    conf_lines+=$'\n'"forward-zone:"
    conf_lines+=$'\n'"    name: \".\""
    conf_lines+=$'\n'"    forward-tls-upstream: yes"

    for resolver in "${resolvers[@]}"; do
        local ip hostname port
        IFS='|' read -r ip hostname port <<< "${resolver}"
        conf_lines+=$'\n'"    forward-addr: ${ip}@${port}#${hostname}"
    done

    write_file "/etc/unbound/conf.d/10-secure-oss-dot.conf" "${conf_lines}"

    # Disable DNSSEC validation conflicts (unbound validates, upstream already validates)
    run_cmd systemctl restart unbound.service 2>/dev/null \
        || run_cmd systemctl restart systemd-resolved.service 2>/dev/null \
        || warn "Could not restart DNS resolver service — reboot to apply DNS changes"
}

_verify_dns() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would verify: dig +short @127.0.0.1 quad9.net"
        return 0
    fi

    if ! command -v dig &>/dev/null; then
        warn "dig not available — skipping DNS verification"
        return 0
    fi

    if dig +short +timeout=5 @127.0.0.1 quad9.net &>/dev/null; then
        log "DNS resolution verified successfully via local resolver"
    else
        warn "DNS resolution check failed — DNS may not be working correctly"
        warn "Try: dig +short @9.9.9.9 quad9.net"
    fi
}

# ---------------------------------------------------------------------------
# Section 2: DHCP hostname suppression
#
# By default, NetworkManager sends the machine hostname to the DHCP server.
# This leaks the hostname to the local network, allowing network operators to
# identify and track the device. Disabling this costs nothing functionally.
# ---------------------------------------------------------------------------

suppress_dhcp_hostname() {
    local conf_file="/etc/NetworkManager/conf.d/10-secure-oss-dhcp.conf"

    if grep --quiet "dhcp-send-hostname=false" "${conf_file}" 2>/dev/null; then
        log "DHCP hostname suppression already configured — skipping"
        return 0
    fi

    log "Suppressing DHCP hostname sending"

    write_file "${conf_file}" "[connection]
# Prevent sending machine hostname to DHCP server.
# Hostname leakage on the local network allows routers, ISPs, and network
# administrators to identify and track this device by name.
ipv4.dhcp-send-hostname=false
ipv6.dhcp-send-hostname=false"

    # Reload NetworkManager configuration without dropping connections
    warn_if_ssh_will_disconnect
    run_cmd nmcli general reload conf

    mark_applied "dhcp"
}

# ---------------------------------------------------------------------------
# Section 3: MAC address randomization
#
# secureblue enables per-network MAC randomization by default (stable MAC per
# SSID). We upgrade this to per-connection randomization: a new MAC is
# generated on every connection attempt, including reconnects to the same SSID.
# This prevents cross-session tracking even on known networks.
# ---------------------------------------------------------------------------

configure_mac_randomization() {
    local conf_file="/etc/NetworkManager/conf.d/10-secure-oss-mac.conf"

    if grep --quiet "cloned-mac-address=random" "${conf_file}" 2>/dev/null; then
        log "Per-connection MAC randomization already configured — skipping"
        return 0
    fi

    log "Configuring per-connection MAC address randomization"

    write_file "${conf_file}" "[connection]
# Per-connection MAC randomization.
# A new MAC address is generated on every connection attempt, preventing
# cross-session device tracking even on known/saved networks.
# This upgrades secureblue's default per-network (stable-per-ssid) to
# per-connection (fully random on each connect).
ethernet.cloned-mac-address=random
wifi.cloned-mac-address=random

[device]
# Also randomize MAC during Wi-Fi scanning (probe requests)
wifi.scan-rand-mac-address=yes"

    warn_if_ssh_will_disconnect
    run_cmd nmcli general reload conf

    mark_applied "mac"
}

# ---------------------------------------------------------------------------
# Section 4: USBGuard
#
# secureblue installs USBGuard but does not enable it (requires user setup).
# We generate a policy from currently connected devices and enable the service.
#
# SAFETY: We verify at least one HID (input) device is present before enabling.
# Enabling USBGuard with no input devices in the allowlist would lock out the
# user's keyboard/mouse on next login.
# ---------------------------------------------------------------------------

setup_usbguard() {
    # Idempotency: if already enabled and policy exists, skip
    if [[ -f /etc/usbguard/rules.conf ]] \
        && systemctl is-enabled usbguard.service &>/dev/null; then
        log "USBGuard is already configured and enabled — skipping"
        return 0
    fi

    if ! command -v usbguard &>/dev/null; then
        warn "usbguard not found — skipping (expected on secureblue; check image)"
        return 0
    fi

    log "Setting up USBGuard"

    # Safety check: ensure at least one HID device is present
    local hid_count
    hid_count="$(usbguard list-devices 2>/dev/null | grep --count --ignore-case "HID\|keyboard\|mouse" || echo "0")"

    if [[ "${hid_count}" -eq 0 ]]; then
        warn "No HID (keyboard/mouse) USB devices detected."
        warn "Enabling USBGuard without input devices in the policy could lock you out."
        warn "Connect a USB keyboard/mouse and re-run, or manually configure USBGuard."
        warn "Skipping USBGuard setup."
        return 1
    fi

    log "Detected ${hid_count} HID device(s) — safe to generate policy"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would generate policy from current USB devices:"
        usbguard generate-policy 2>/dev/null || true
        echo "[DRY RUN] Would write policy to /etc/usbguard/rules.conf"
        echo "[DRY RUN] Would run: systemctl enable --now usbguard.service"
        return 0
    fi

    # Create required directories with correct ownership and SELinux context
    mkdir --parents /etc/usbguard /var/log/usbguard
    restorecon -vR /etc/usbguard /var/log/usbguard 2>/dev/null || true

    # Generate policy from currently connected devices
    log "Generating USBGuard policy from connected devices..."
    usbguard generate-policy > /etc/usbguard/rules.conf
    chmod 600 /etc/usbguard/rules.conf
    restorecon -v /etc/usbguard/rules.conf 2>/dev/null || true

    log "Generated policy:"
    cat /etc/usbguard/rules.conf

    # Enable the service
    systemctl enable --now usbguard.service

    log "USBGuard enabled. Any USB device not present at this time will be blocked."
    log "To allow a new device: usbguard allow-device <ID> --permanent"

    mark_applied "usbguard"
}

# ---------------------------------------------------------------------------
# Section 5: MDM domain blocking
#
# Null-routes known MDM/RMM enrollment and management infrastructure via
# /etc/hosts. This prevents MDM agents from calling home to their control
# plane, disables device enrollment, and blocks OEM/employer-pushed management.
#
# Note: /etc/hosts blocking works for hostname-based lookups. It does not
# block IP-direct connections. However, MDM infrastructure relies on hostnames
# for TLS certificate validation and is thus effectively blocked.
# ---------------------------------------------------------------------------

block_mdm_domains() {
    local blocklist="${SCRIPT_DIR}/lib/hosts-mdm.txt"

    if [[ ! -f "${blocklist}" ]]; then
        warn "MDM blocklist not found: ${blocklist} — skipping"
        return 1
    fi

    log "Applying MDM domain blocklist to /etc/hosts"
    _apply_hosts_blocklist "${blocklist}" "MDM"
    mark_applied "mdm"
}

# ---------------------------------------------------------------------------
# Section 6: Telemetry domain blocking
#
# Null-routes known telemetry, crash reporting, and analytics endpoints.
# See lib/hosts-telemetry.txt for the domain list and caveat notes.
# ---------------------------------------------------------------------------

block_telemetry_domains() {
    local blocklist="${SCRIPT_DIR}/lib/hosts-telemetry.txt"

    if [[ ! -f "${blocklist}" ]]; then
        warn "Telemetry blocklist not found: ${blocklist} — skipping"
        return 1
    fi

    log "Applying telemetry domain blocklist to /etc/hosts"
    _apply_hosts_blocklist "${blocklist}" "TELEMETRY"
    mark_applied "telemetry"
}

# Shared /etc/hosts block writer
# Args: BLOCKLIST_FILE LABEL
_apply_hosts_blocklist() {
    local blocklist="$1"
    local label="$2"
    local begin_marker="### BEGIN secure_oss ${label} BLOCK — DO NOT EDIT ###"
    local end_marker="### END secure_oss ${label} BLOCK ###"

    # Build the hosts entries from the blocklist file
    # Skip comment lines and empty lines; format as: 0.0.0.0  domain
    local entries
    entries="$(grep --extended-regexp --invert-match '^[[:space:]]*#|^[[:space:]]*$' "${blocklist}" \
        | awk '{printf "0.0.0.0  %s\n", $1}')"

    local count
    count="$(echo "${entries}" | wc --lines)"
    log "Blocking ${count} domains from ${blocklist}"

    append_block "/etc/hosts" "${begin_marker}" "${end_marker}" "${entries}"
}

# ---------------------------------------------------------------------------
# Section 7: Cockpit masking
#
# Cockpit is GNOME/Fedora's web-based system administration console.
# It exposes a local HTTP server and may allow remote management when enabled.
# We mask the socket activation unit to prevent any start, even if installed
# later. Masking (not just disabling) is resilient to package reinstalls.
# ---------------------------------------------------------------------------

mask_cockpit() {
    if ! systemctl cat cockpit.socket &>/dev/null; then
        log "cockpit.socket not present — skipping"
        return 0
    fi

    if systemctl is-enabled cockpit.socket 2>/dev/null | grep --quiet "masked"; then
        log "cockpit.socket already masked — skipping"
        return 0
    fi

    log "Masking cockpit.socket and cockpit.service (web-based remote admin)"
    run_cmd systemctl mask cockpit.socket
    run_cmd systemctl stop cockpit.socket cockpit.service 2>/dev/null || true

    mark_applied "cockpit"
}

# ---------------------------------------------------------------------------
# Section 8: ABRT masking
#
# ABRT (Automatic Bug Reporting Tool) collects crash data and sends it to
# Red Hat's infrastructure. On Silverblue/secureblue it may not be installed,
# but we mask all known ABRT units defensively in case any are present.
# We mask rather than rpm-ostree remove to avoid requiring a reboot.
# ---------------------------------------------------------------------------

mask_abrt() {
    local abrt_units=(
        abrt.service
        abrtd.service
        abrt-ccpp.service
        abrt-oops.service
        abrt-journal-core.service
        abrt-pstoreoops.service
        abrt-vmcore.service
        abrt-xorg.service
        abrt-dump-journal-core.service
    )

    local masked_count=0

    for unit in "${abrt_units[@]}"; do
        if systemctl cat "${unit}" &>/dev/null; then
            if ! systemctl is-enabled "${unit}" 2>/dev/null | grep --quiet "masked"; then
                log "Masking ${unit}"
                run_cmd systemctl mask "${unit}"
                ((masked_count++)) || true
            else
                log "${unit} already masked"
            fi
        fi
    done

    if [[ "${masked_count}" -eq 0 ]]; then
        log "No ABRT units found or all already masked — nothing to do"
    else
        log "Masked ${masked_count} ABRT unit(s)"
    fi

    mark_applied "abrt"
}

# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo -e "${_BOLD}=== Hardening Summary ===${_RESET}"
    echo ""

    local sections=(dns dhcp mac usbguard mdm telemetry cockpit abrt)
    for section in "${sections[@]}"; do
        if is_applied "${section}"; then
            echo -e "  ${_GREEN}✓${_RESET} ${section}"
        elif should_skip "${section}"; then
            echo -e "  ${_YELLOW}−${_RESET} ${section} (skipped)"
        else
            echo -e "  ${_RED}✗${_RESET} ${section} (not applied or failed)"
        fi
    done

    echo ""

    if [[ "${_FAILED}" -eq 1 ]]; then
        warn "One or more sections encountered errors. Review the output above."
        warn "Log file: ${LOG_FILE}"
    else
        log "All sections completed successfully."
    fi

    echo ""
    echo "Optional hardening steps (run separately):"
    echo "  sudo bash optional/disable-webcam.sh   — disable USB webcam kernel module"
    echo "  sudo bash optional/bash-lockdown.sh    — make shell config files immutable"
    echo "  sudo bash optional/wireguard-killswitch.sh — configure WireGuard kill-switch"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    mkdir --parents /var/log "${MARKER_DIR}"
    log "=== secure_oss harden.sh v${SCRIPT_VERSION} ==="

    require_root
    require_secureblue
    check_reboot_pending

    run_section "dns"       configure_dns
    run_section "dhcp"      suppress_dhcp_hostname
    run_section "mac"       configure_mac_randomization
    run_section "usbguard"  setup_usbguard
    run_section "mdm"       block_mdm_domains
    run_section "telemetry" block_telemetry_domains
    run_section "cockpit"   mask_cockpit
    run_section "abrt"      mask_abrt

    # Remove the reboot sentinel from provision.sh now that harden.sh has run
    clear_reboot_pending

    print_summary

    if [[ "${_FAILED}" -ne 0 ]]; then
        exit 1
    fi
}

main "$@"
