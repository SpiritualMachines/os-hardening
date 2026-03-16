#!/usr/bin/env bash
# harden.sh — Light hardening for vanilla Fedora Silverblue
#
# Platform  : Fedora Silverblue (vanilla — no secureblue rebase required)
# Purpose   : Low-friction hardening baseline: default-deny inbound firewall,
#             mask unnecessary/insecure services, sysctl network hardening,
#             DHCP hostname suppression, and MAC address randomization.
#             All changes are written to /etc or applied via systemctl/firewall-cmd —
#             no /usr writes (respects the immutable base layer).
# Tested on : Fedora Silverblue 41
# Requires  : root, Fedora Silverblue (or any Fedora Atomic variant), internet
#             access is NOT required
#
# Usage:
#   sudo bash harden.sh [--dry-run] [--skip SECTION]
#
# Skip sections (--skip, comma-separated):
#   firewall, services, sysctl, dhcp, mac, abrt, cockpit, amt, monitor
#
# Sections applied:
#   1. Firewall      — Set default firewalld zone to drop (default-deny inbound)
#   2. Services      — Mask avahi-daemon, rpcbind, geoclue, ModemManager
#   3. Sysctl        — Network stack and kernel hardening parameters
#   4. DHCP          — Suppress hostname leakage on LAN
#   5. MAC           — Per-connection MAC address randomization
#   6. ABRT          — Mask Automatic Bug Reporting Tool (crash data collection)
#   7. Cockpit       — Mask web-based remote administration console
#
# Verification:
#   Firewall  : firewall-cmd --get-default-zone  (should show "drop")
#               firewall-cmd --list-all --zone=drop
#   Services  : systemctl is-enabled avahi-daemon.service
#   Sysctl    : sysctl net.ipv4.conf.all.accept_redirects
#   DHCP      : cat /etc/NetworkManager/conf.d/10-secure-oss-light-dhcp.conf
#   MAC       : nmcli -f GENERAL.HWADDR,802-11-wireless.mac-address-randomization dev show
#   ABRT      : systemctl is-enabled abrtd.service  (should show "masked")
#   Cockpit   : systemctl is-enabled cockpit.socket  (should show "masked")

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SKIP_SECTIONS=()

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash harden.sh [OPTIONS]

Apply light hardening to a vanilla Fedora Silverblue system.
No rebase or reboot is required.

Options:
  --skip SECTIONS   Comma-separated list of sections to skip
                    Values: firewall, services, sysctl, dhcp, mac, abrt, cockpit, monitor
  --dry-run         Show what would be done without making changes
  --help            Show this help

Examples:
  sudo bash harden.sh
  sudo bash harden.sh --dry-run
  sudo bash harden.sh --skip mac,abrt
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
# Section 1: Firewall — default-deny all inbound
#
# Firewalld's "drop" zone silently drops all unsolicited inbound packets.
# Established/related return traffic (e.g. your browser responses) is handled
# by conntrack and is NOT affected — outbound-initiated connections work normally.
# IPv4 DHCP works via conntrack (kernel tracks the DISCOVER/OFFER exchange).
# We explicitly add dhcpv6-client to the drop zone to support IPv6 SLAAC/DHCPv6.
#
# Why "drop" vs "block": "drop" silently discards packets; "block" sends
# ICMP unreachable back to the sender. Drop is preferable for security — it
# provides no information to port scanners about which ports exist.
# ---------------------------------------------------------------------------

configure_firewall() {
    if ! command -v firewall-cmd &>/dev/null; then
        warn "firewall-cmd not found — is firewalld installed? Skipping."
        return 1
    fi

    if is_applied "firewall"; then
        log "Firewall already configured — skipping (delete ${MARKER_DIR}/firewall to re-apply)"
        return 0
    fi

    local current_zone
    current_zone="$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")"
    log "Current default zone: ${current_zone}"

    if [[ "${current_zone}" == "drop" ]]; then
        log "Default zone is already 'drop' — verifying dhcpv6-client is present..."
        _ensure_dhcpv6_in_drop_zone
        mark_applied "firewall"
        return 0
    fi

    log "Setting default firewalld zone to 'drop' (default-deny all inbound)"
    log "Established/return traffic and outbound connections are unaffected."

    # Set the default zone to drop — new network interfaces will use this zone
    run_cmd firewall-cmd --permanent --set-default-zone=drop

    # Add dhcpv6-client to the drop zone so IPv6 autoconfiguration works.
    # Without this, DHCPv6/SLAAC reply packets would be dropped and IPv6
    # addressing via DHCP would fail on networks that require it.
    _ensure_dhcpv6_in_drop_zone

    # Move all active interfaces to the drop zone so the change takes effect
    # immediately without requiring a reboot or firewalld restart.
    _reassign_active_interfaces_to_drop

    # Reload to apply permanent changes
    run_cmd firewall-cmd --reload

    log "Default zone is now 'drop'. All unsolicited inbound traffic is blocked."
    log "To open a port: firewall-cmd --permanent --zone=drop --add-port=<PORT>/tcp && firewall-cmd --reload"

    mark_applied "firewall"
}

_ensure_dhcpv6_in_drop_zone() {
    # Check if dhcpv6-client is already in the drop zone (permanent config)
    if firewall-cmd --permanent --zone=drop --query-service=dhcpv6-client &>/dev/null; then
        log "dhcpv6-client already in drop zone — no change needed"
        return 0
    fi

    log "Adding dhcpv6-client service to drop zone (required for IPv6 addressing)"
    run_cmd firewall-cmd --permanent --zone=drop --add-service=dhcpv6-client
}

_reassign_active_interfaces_to_drop() {
    # Move each currently active NM-managed interface to the drop zone so the
    # hardening takes effect immediately for the current session, not just after reboot.
    local interfaces
    interfaces="$(nmcli -t -f DEVICE,TYPE device status 2>/dev/null \
        | grep -v '^lo:' \
        | awk -F: '{print $1}')" || interfaces=""

    if [[ -z "${interfaces}" ]]; then
        warn "No active network interfaces detected — zone reassignment skipped"
        return 0
    fi

    while IFS= read -r iface; do
        [[ -z "${iface}" ]] && continue
        local current_iface_zone
        current_iface_zone="$(firewall-cmd --get-zone-of-interface="${iface}" 2>/dev/null || echo "none")"
        if [[ "${current_iface_zone}" != "drop" ]]; then
            log "Moving interface '${iface}' from zone '${current_iface_zone}' to 'drop'"
            run_cmd firewall-cmd --zone=drop --change-interface="${iface}" || \
                warn "Could not reassign interface '${iface}' — it will use drop zone after reboot"
        else
            log "Interface '${iface}' already in drop zone"
        fi
    done <<< "${interfaces}"
}

# ---------------------------------------------------------------------------
# Section 2: Services — mask unnecessary/insecure services
#
# These services are either rarely needed on a personal Silverblue desktop or
# represent attack surface that adds no value for most users:
#
#   avahi-daemon   mDNS/DNS-SD responder. Announces the device on the local
#                  network by hostname, enabling passive device tracking and
#                  name-based enumeration. Not required for typical desktop use.
#                  (System DNS and manual /etc/hosts entries cover local needs.)
#
#   rpcbind        RPC portmapper. Required only for NFS. Exposes an open port
#                  and is a historic source of vulnerabilities. Masked unless
#                  you use NFS mounts.
#
#   geoclue        Location services daemon. Provides GPS/Wi-Fi location data
#                  to applications. Unnecessary if you don't use location-aware
#                  apps, and a potential privacy concern.
#
#   ModemManager   Mobile broadband modem manager. Unnecessary on systems
#                  without a cellular modem. Adds D-Bus surface and auto-probes
#                  serial ports.
# ---------------------------------------------------------------------------

mask_services() {
    # Services that are safe to mask on a typical Silverblue desktop.
    # Format: "unit:reason"
    local services_to_mask=(
        "avahi-daemon.service:mDNS responder — announces hostname on LAN, enables device tracking"
        "avahi-daemon.socket:mDNS responder socket activation"
        "rpcbind.service:RPC portmapper — only needed for NFS; exposes an open port"
        "rpcbind.socket:RPC portmapper socket activation"
        "geoclue.service:Location services — unnecessary without location-aware apps"
        "ModemManager.service:Mobile modem manager — unnecessary without cellular hardware"
    )

    local masked_count=0

    for entry in "${services_to_mask[@]}"; do
        local unit="${entry%%:*}"
        local reason="${entry#*:}"

        if ! systemctl cat "${unit}" &>/dev/null; then
            log "${unit} not present on this system — skipping"
            continue
        fi

        if systemctl is-enabled "${unit}" 2>/dev/null | grep --quiet "masked"; then
            log "${unit} already masked"
            continue
        fi

        log "Masking ${unit} — ${reason}"
        run_cmd systemctl mask "${unit}"
        run_cmd systemctl stop "${unit}" 2>/dev/null || true
        ((masked_count++)) || true
    done

    if [[ "${masked_count}" -eq 0 ]]; then
        log "All targeted services were already masked or not present."
    else
        log "Masked ${masked_count} service(s)."
    fi

    mark_applied "services"
}

# ---------------------------------------------------------------------------
# Section 3: Sysctl — network stack and kernel hardening
#
# These parameters harden the kernel network stack and restrict information
# leakage. All values are non-disruptive for normal desktop/workstation use.
#
# References:
#   - https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
#   - CIS Fedora Linux Benchmark (Level 1 controls)
#   - ANSSI Linux Configuration Guide
# ---------------------------------------------------------------------------

configure_sysctl() {
    local conf_file="/etc/sysctl.d/90-secure-oss-light.conf"

    if [[ -f "${conf_file}" ]]; then
        log "sysctl config already present at ${conf_file} — skipping"
        log "Delete ${conf_file} and re-run to regenerate."
        return 0
    fi

    log "Writing sysctl hardening parameters to ${conf_file}"

    write_file "${conf_file}" "# secure_oss-light: kernel and network stack hardening
# Applied by harden.sh — see comments for rationale.
# Safe to re-apply; parameters take effect on next sysctl --system or reboot.

# --- IPv4: disable ICMP redirect acceptance ---
# Routers can send ICMP redirects to alter the routing table.
# An attacker on the local network can forge redirects to redirect traffic
# through a malicious host (MITM). Desktop systems should never accept these.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# --- IPv4: disable secure ICMP redirect acceptance (RFC 1122 secure mode) ---
# Even 'secure' redirects (only from gateways in the routing table) are
# unnecessary for a workstation and can be abused in some configurations.
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# --- IPv4: disable sending ICMP redirects ---
# A workstation is not a router and should never send routing redirects.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# --- IPv6: disable ICMP redirect acceptance ---
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- Disable source routing ---
# Source-routed packets specify their own path through the network.
# This is almost never legitimate and is used in spoofing/hijacking attacks.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- TCP SYN cookies ---
# Protects against SYN flood DoS attacks by not allocating state until
# the three-way handshake completes. No performance impact on normal traffic.
net.ipv4.tcp_syncookies = 1

# --- Reverse path filtering (rp_filter) ---
# Drops packets that arrive on an interface but whose source address would
# not be routed back through that same interface. Prevents IP spoofing.
# Mode 1 = strict (recommended); mode 2 = loose (for multi-homed systems).
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Log martian packets ---
# Log packets with impossible source addresses (e.g., loopback addresses
# arriving on a physical interface). Useful for detecting spoofing attempts.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Ignore ICMP broadcast pings (Smurf attack mitigation) ---
# A host responding to broadcast pings can be used as an amplifier in
# Smurf DDoS attacks. Ignoring broadcast pings has no user-visible impact.
net.ipv4.icmp_echo_ignore_broadcasts = 1

# --- Ignore bogus ICMP error responses ---
# Silently discard malformed ICMP error responses. Prevents log spam and
# potential information leakage from crafted error packets.
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Restrict dmesg to root ---
# Prevents unprivileged users from reading the kernel ring buffer, which
# can contain sensitive information such as memory addresses useful for
# defeating ASLR, hardware serial numbers, and kernel pointers.
kernel.dmesg_restrict = 1

# --- Hide kernel pointers from unprivileged users ---
# Kernel pointer values exposed via /proc and similar interfaces can be
# used to defeat KASLR. Value 2 replaces them with 0x0 for all users
# (including root unless using CAP_SYSLOG). Value 1 hides from non-root.
kernel.kptr_restrict = 1

# --- Harden BPF JIT compiler ---
# The BPF JIT can expose kernel addresses. Hardening mode 2 randomizes
# JIT memory allocation and enables constant blinding to resist JIT spraying.
# Note: Silverblue/Fedora may already set this; this is idempotent.
net.core.bpf_jit_harden = 2

# --- Disable IPv6 router advertisement acceptance (if using static/DHCP IPv6) ---
# Router advertisements are legitimate for SLAAC-based IPv6 autoconfiguration.
# Leaving this at default (1 = accept RA, configure autoconfiguration).
# Uncomment the lines below ONLY if you use purely static or DHCPv6-only IPv6
# and want to reject RA-based autoconfiguration:
# net.ipv6.conf.all.accept_ra = 0
# net.ipv6.conf.default.accept_ra = 0"

    if [[ "${DRY_RUN}" != "1" ]]; then
        log "Applying sysctl parameters immediately (no reboot needed)..."
        sysctl --system 2>/dev/null | grep --fixed-strings "secure-oss" || \
            sysctl -p "${conf_file}" 2>/dev/null || \
            warn "Could not apply sysctl parameters immediately — they will take effect on next reboot"
    fi

    mark_applied "sysctl"
}

# ---------------------------------------------------------------------------
# Section 4: DHCP hostname suppression
#
# By default, NetworkManager sends the machine hostname to the DHCP server
# on every DHCP request. The DHCP server (your router) logs and may display
# this hostname, allowing network operators or anyone with router access to
# identify and track this device by name. Disabling it has no functional cost.
# ---------------------------------------------------------------------------

suppress_dhcp_hostname() {
    local conf_file="/etc/NetworkManager/conf.d/10-secure-oss-light-dhcp.conf"

    if [[ -f "${conf_file}" ]]; then
        log "DHCP hostname suppression already configured at ${conf_file} — skipping"
        return 0
    fi

    log "Suppressing DHCP hostname sending (prevents hostname leakage to router/LAN)"

    write_file "${conf_file}" "[connection]
# Prevent sending the machine hostname to the DHCP server.
# Without this, your router logs your device name alongside its IP and MAC,
# making it trivially identifiable on the local network.
ipv4.dhcp-send-hostname=false
ipv6.dhcp-send-hostname=false"

    # Reload NetworkManager configuration without dropping active connections
    warn_if_ssh_will_disconnect
    run_cmd nmcli general reload conf

    mark_applied "dhcp"
}

# ---------------------------------------------------------------------------
# Section 5: MAC address randomization
#
# By default, NetworkManager uses the hardware (burned-in) MAC address for
# all connections. This allows Wi-Fi access points, captive portals, and
# passive observers to track the device across networks and over time.
#
# Per-connection randomization generates a new MAC on every connection
# attempt, including reconnects to saved networks. This prevents all
# MAC-based tracking. There is no functional downside for typical desktop use.
#
# Note: Some enterprise Wi-Fi networks tie authentication to MAC address.
# If you use 802.1X with MAC-based auth, skip this section with --skip mac.
# ---------------------------------------------------------------------------

configure_mac_randomization() {
    local conf_file="/etc/NetworkManager/conf.d/10-secure-oss-light-mac.conf"

    if [[ -f "${conf_file}" ]]; then
        log "MAC randomization already configured at ${conf_file} — skipping"
        return 0
    fi

    log "Configuring per-connection MAC address randomization"

    write_file "${conf_file}" "[connection]
# Per-connection MAC address randomization.
# A fresh random MAC is generated on every connection attempt, preventing
# tracking by access points, routers, and passive Wi-Fi scanners.
# To disable per-profile: nmcli connection modify <NAME> wifi.cloned-mac-address preserve
ethernet.cloned-mac-address=random
wifi.cloned-mac-address=random

[device]
# Randomize MAC during Wi-Fi scanning (probe requests broadcast your presence).
# Without this, probe requests use the real hardware MAC even before associating.
wifi.scan-rand-mac-address=yes"

    warn_if_ssh_will_disconnect
    run_cmd nmcli general reload conf

    mark_applied "mac"
}

# ---------------------------------------------------------------------------
# Section 6: ABRT — mask crash data collection
#
# ABRT (Automatic Bug Reporting Tool) automatically captures crash data and
# can upload it to Red Hat's infrastructure (retrace servers). While useful
# for bug reporting, it collects detailed system and application state that
# may contain sensitive data, and sends it to a third party.
#
# We mask all known ABRT units. Masking (vs disabling) survives package
# reinstalls and prevents socket-based activation from bringing it back.
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
        if ! systemctl cat "${unit}" &>/dev/null; then
            continue
        fi
        if systemctl is-enabled "${unit}" 2>/dev/null | grep --quiet "masked"; then
            log "${unit} already masked"
            continue
        fi
        log "Masking ${unit} (ABRT crash reporter)"
        run_cmd systemctl mask "${unit}"
        ((masked_count++)) || true
    done

    if [[ "${masked_count}" -eq 0 ]]; then
        log "No ABRT units found or all already masked — nothing to do"
    else
        log "Masked ${masked_count} ABRT unit(s)"
    fi

    mark_applied "abrt"
}

# ---------------------------------------------------------------------------
# Section 7: Cockpit — mask web-based admin console
#
# Cockpit provides a browser-based system administration interface. When
# enabled, it opens a local HTTP/WebSocket listener (default port 9090) and
# can expose remote management capabilities. It is not typically needed on a
# personal workstation and represents unnecessary attack surface.
#
# We mask cockpit.socket (the socket-activated listener) and cockpit.service.
# Masking the socket prevents activation even after a package update restores
# the unit file.
# ---------------------------------------------------------------------------

mask_cockpit() {
    local cockpit_units=(
        cockpit.socket
        cockpit.service
    )

    if ! systemctl cat cockpit.socket &>/dev/null; then
        log "cockpit.socket not present on this system — skipping"
        mark_applied "cockpit"
        return 0
    fi

    local masked_count=0

    for unit in "${cockpit_units[@]}"; do
        if ! systemctl cat "${unit}" &>/dev/null; then
            continue
        fi
        if systemctl is-enabled "${unit}" 2>/dev/null | grep --quiet "masked"; then
            log "${unit} already masked"
            continue
        fi
        log "Masking ${unit} (web-based remote administration)"
        run_cmd systemctl mask "${unit}"
        run_cmd systemctl stop "${unit}" 2>/dev/null || true
        ((masked_count++)) || true
    done

    if [[ "${masked_count}" -eq 0 ]]; then
        log "Cockpit units already masked — nothing to do"
    else
        log "Masked ${masked_count} Cockpit unit(s)"
    fi

    mark_applied "cockpit"
}

# ---------------------------------------------------------------------------
# Section 8: Intel ME/AMT hardening
#
# Intel Management Engine (ME) is a separate microcontroller running at
# Ring -3, independent of the OS. AMT (Active Management Technology) is
# an ME feature providing out-of-band remote management reachable even
# when the OS is off or crashed.
#
# ┌──────────────────────────────────────────────────────────────────┐
# │  HARD LIMIT — what OS-level hardening CANNOT do:                │
# │                                                                  │
# │  In shared-NIC mode, AMT intercepts TCP/UDP packets on its ports │
# │  BEFORE the kernel network stack sees them. firewalld rules DO  │
# │  NOT block network-level AMT access.                            │
# │                                                                  │
# │  Primary mitigation: disable AMT/ME in BIOS/MEBx, then apply   │
# │  Intel firmware updates (INTEL-SA security advisories).         │
# └──────────────────────────────────────────────────────────────────┘
#
# What this section achieves:
#   1. Blacklists mei_me and mei_wdt kernel modules — severs the kernel's
#      channel to the ME firmware (requires reboot)
#   2. Checks whether AMT ports are visible in the OS network stack
#   3. Deploys a monitor that alerts if mei_me is (re-)loaded or AMT
#      ports appear in the OS stack
#
# Verification:
#   cat /etc/modprobe.d/secure-oss-amt.conf
#   lsmod | grep mei_me    (nothing expected after reboot)
#   journalctl -t secure-oss-light --since '-24h' | grep -i amt
# ---------------------------------------------------------------------------

harden_amt() {
    local has_me=0
    if lspci 2>/dev/null | grep --quiet --ignore-case 'management engine\|MEI controller\|HECI'; then
        has_me=1
    elif ls /dev/mei* &>/dev/null 2>&1; then
        has_me=1
    fi

    if [[ "${has_me}" -eq 0 ]]; then
        log "No Intel Management Engine device detected — skipping AMT hardening"
        mark_applied "amt"
        return 0
    fi

    log "Intel ME device detected — applying AMT/ME hardening"

    local amt_modprobe="/etc/modprobe.d/secure-oss-amt.conf"
    local amt_check_script="/usr/local/lib/secure-oss-light/amt-check.sh"
    local scan_dropin_dir="/etc/systemd/system/secure-oss-light-monitor.service.d"

    # --- 1. Blacklist MEI kernel modules ---

    write_file "${amt_modprobe}" "# secure_oss: Intel Management Engine kernel module restrictions
# Applied by harden.sh (amt section).
# Reboot required for blacklist to take full effect.
#
# mei_me  — OS-to-ME communication driver. Blacklisting severs the kernel's
#           channel to ME firmware. ME hardware continues at Ring -3.
#           May affect Intel SGX, Intel PTT, or UEFI Secure Boot workflows.
#           Remove this file if those features are needed.
# mei_wdt — ME-driven hardware watchdog. Not needed on desktop systems.
blacklist mei_me
blacklist mei_wdt
install mei_me /bin/false
install mei_wdt /bin/false"

    if [[ "${DRY_RUN}" != "1" ]]; then
        rmmod mei_wdt 2>/dev/null || true
        if ! lsmod 2>/dev/null | awk 'NR>1 {print $4}' | tr ',' '\n' | grep --quiet '^mei_me$'; then
            rmmod mei_me 2>/dev/null || true
        else
            warn "mei_me has dependent modules — it will be blocked on next reboot"
        fi
    fi

    # --- 2. AMT provisioning check ---

    log "Checking for AMT port listeners (fallback — install mei-amt-check for definitive check)"
    log "https://github.com/mjg59/mei-amt-check"
    if [[ "${DRY_RUN}" != "1" ]]; then
        local amt_listeners
        amt_listeners="$(ss --tcp --listening --numeric 2>/dev/null \
            | awk '{print $4}' \
            | grep --extended-regexp ':16992$|:16993$|:16994$|:16995$|:623$|:664$' || true)"
        if [[ -n "${amt_listeners}" ]]; then
            warn "AMT management ports are listening in OS network stack: ${amt_listeners}"
            warn "AMT is provisioned and active. Disable in BIOS/MEBx immediately."
        else
            log "AMT ports not visible in OS network stack (expected in shared-NIC mode)."
            log "Verify AMT state in BIOS/MEBx — port absence does NOT confirm AMT is off."
        fi
    fi

    # --- 3. Deploy AMT-specific monitor ---

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would write: ${amt_check_script}"
        echo "[DRY RUN] Would hook into or create AMT check timer"
    else
        mkdir --parents /usr/local/lib/secure-oss-light

        cat > "${amt_check_script}" <<'AMT_EOF'
#!/usr/bin/env bash
# secure-oss-light AMT monitor
# Deployed by harden.sh (amt section).
set -uo pipefail

_amt_alert() {
    local msg="$1"
    logger -p security.warning -t secure-oss-light "[AMT ALERT] ${msg}"
    {
        printf '\n'
        printf '┌──────────────────────────────────────────────────────────────┐\n'
        printf '│  ⚠  SECURE-OSS AMT/ME ALERT                                 │\n'
        printf '│  %-62s │\n' "${msg}"
        printf '│  journalctl -t secure-oss-light --since "-1h"               │\n'
        printf '└──────────────────────────────────────────────────────────────┘\n'
    } | wall --nobanner 2>/dev/null || wall 2>/dev/null || true
    while IFS= read -r uid; do
        [[ "${uid}" =~ ^[0-9]+$ ]] || continue
        local dbus_sock="/run/user/${uid}/bus"
        [[ -S "${dbus_sock}" ]] || continue
        local username
        username="$(id -nu "${uid}" 2>/dev/null)" || continue
        su -s /bin/bash "${username}" -- -c \
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${uid}/bus \
             notify-send --urgency=critical --expire-time=0 \
               --app-name=secure-oss --icon=dialog-warning \
               'AMT/ME Security Alert' '${msg}'" \
            2>/dev/null || true
    done < <(loginctl list-users --no-legend 2>/dev/null | awk '{print $1}')
}

# Check 1: mei_me module re-loaded after being blacklisted
if lsmod 2>/dev/null | grep --quiet '^mei_me'; then
    _amt_alert "Intel MEI module (mei_me) is loaded — ME kernel interface is active. Blacklisted by secure-oss; verify /etc/modprobe.d/secure-oss-amt.conf and reboot."
fi

# Check 2: AMT ports visible in OS network stack
amt_listeners="$(ss --tcp --listening --numeric 2>/dev/null \
    | awk '{print $4}' \
    | grep --extended-regexp ':16992$|:16993$|:16994$|:16995$|:623$|:664$' || true)"
if [[ -n "${amt_listeners}" ]]; then
    _amt_alert "AMT management port visible in OS network stack: ${amt_listeners} — AMT is provisioned and accessible via the OS path"
fi

logger -p security.info -t secure-oss-light "AMT check complete"
AMT_EOF

        chmod 700 "${amt_check_script}"
        restorecon -v "${amt_check_script}" 2>/dev/null || true

        # Hook into existing light monitor service if present; otherwise create own timer
        if systemctl cat secure-oss-light-monitor.service &>/dev/null; then
            mkdir --parents "${scan_dropin_dir}"
            cat > "${scan_dropin_dir}/50-amt.conf" <<'DROPIN_EOF'
# secure-oss amt section: extend light monitor with AMT checks
[Service]
ExecStart=/usr/local/lib/secure-oss-light/amt-check.sh
DROPIN_EOF
            systemctl daemon-reload
            log "AMT check added to existing light monitor timer via service drop-in"
        else
            cat > /etc/systemd/system/secure-oss-light-amt-check.service <<'SVC_EOF'
[Unit]
Description=secure-oss-light Intel AMT monitor (one-shot)
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/secure-oss-light/amt-check.sh
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secure-oss-light-monitor
SVC_EOF
            cat > /etc/systemd/system/secure-oss-light-amt-check.timer <<'TIMER_EOF'
[Unit]
Description=secure-oss-light Intel AMT monitor timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Unit=secure-oss-light-amt-check.service
AccuracySec=1min

[Install]
WantedBy=timers.target
TIMER_EOF
            systemctl daemon-reload
            systemctl enable --now secure-oss-light-amt-check.timer
            log "Standalone AMT check timer created (runs every 15 minutes)"
        fi
    fi

    warn ""
    warn "╔══════════════════════════════════════════════════════════════╗"
    warn "║  INTEL AMT/ME — EFFECTIVE MITIGATIONS                       ║"
    warn "╠══════════════════════════════════════════════════════════════╣"
    warn "║  AMT intercepts packets BEFORE the OS kernel sees them.     ║"
    warn "║  This host's firewall does NOT protect against AMT access.  ║"
    warn "║                                                              ║"
    warn "║  RECOMMENDED (most practical):                               ║"
    warn "║  Block AMT ports on your GATEWAY/ROUTER — this works        ║"
    warn "║  because the gateway is a separate device upstream of the   ║"
    warn "║  NIC. Ports to block: TCP 16992-16995, 664 / UDP 623        ║"
    warn "║  Caveat: does not stop attackers already on your LAN.       ║"
    warn "║  Use VLAN isolation for full LAN-level protection.          ║"
    warn "║                                                              ║"
    warn "║  ALSO RECOMMENDED:                                           ║"
    warn "║  1. Disable AMT in BIOS/MEBx if your board exposes it       ║"
    warn "║     Reboot → Ctrl+P at POST → MEBx → ME Features Setup     ║"
    warn "║  2. Apply Intel firmware security updates (INTEL-SA-*)      ║"
    warn "║  3. Install mei-amt-check to verify provisioning state:     ║"
    warn "║     https://github.com/mjg59/mei-amt-check                 ║"
    warn "╚══════════════════════════════════════════════════════════════╝"
    warn ""

    mark_applied "amt"
}

# ---------------------------------------------------------------------------
# Section 9: MDM/RMM intrusion monitoring
#
# Deploys a timer-based monitor (poll every 2 minutes) that detects signs of
# MDM enrollment or remote management tool installation. No extra packages are
# required — Silverblue's immutable base means inotify-tools can only be added
# via rpm-ostree layering, so this uses checksum-based polling instead.
#
# Detects:
#   - Changes to /etc/ssh/sshd_config, /etc/sudoers, /root/.ssh/authorized_keys
#     (baseline recorded on first run, alerts if checksum changes)
#   - New systemd service files created in /etc/systemd/system/
#   - Known RMM/remote-management process names (TeamViewer, AnyDesk, etc.)
#
# Alerts via: wall (all terminals) + logger (journal) + notify-send (desktop)
# State (checksum baselines) stored in: /var/lib/secure-oss-light/monitor/
#
# Verification:
#   systemctl status secure-oss-light-monitor.timer
#   journalctl -t secure-oss-light --since '-24h'
# ---------------------------------------------------------------------------

setup_monitoring() {
    local monitor_script="/usr/local/lib/secure-oss-light/monitor.sh"
    local monitor_svc="/etc/systemd/system/secure-oss-light-monitor.service"
    local monitor_timer="/etc/systemd/system/secure-oss-light-monitor.timer"

    if is_applied "monitor"; then
        log "MDM/RMM monitoring already configured — skipping"
        return 0
    fi

    log "Setting up MDM/RMM intrusion monitoring (poll-based, no extra packages)"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would write: ${monitor_script}"
        echo "[DRY RUN] Would write: ${monitor_svc}"
        echo "[DRY RUN] Would write: ${monitor_timer}"
        echo "[DRY RUN] Would enable: secure-oss-light-monitor.timer"
        return 0
    fi

    mkdir --parents /usr/local/lib/secure-oss-light
    mkdir --parents /var/lib/secure-oss-light/monitor
    restorecon -vR /usr/local/lib/secure-oss-light 2>/dev/null || true

    log "Writing ${monitor_script}"
    cat > "${monitor_script}" <<'MONITOR_EOF'
#!/usr/bin/env bash
# secure-oss-light-monitor — MDM/RMM intrusion detection (poll-based)
# Managed by harden.sh — do not edit manually.
# Called by systemd timer every 2 minutes.
set -uo pipefail

STATE_DIR="/var/lib/secure-oss-light/monitor"

# Known RMM/remote-management process names.
# This list covers common commercial RMM tools but is not exhaustive —
# new agents and rebranded tools appear regularly. Extend this list to
# match any additional tools relevant to your environment.
RMM_PROCS=(
    teamviewerd anydesk dwagent dcsystemservice
    kaseya agentmon splashtop_streamer bomgar-scc
    pulsewaymgr ninjaone ninjarmmagent connectwise
    cwautomate screenconnect remotepc goto-agent
    zohoassist atera
)

# Files to track for unexpected modifications (checksum baseline)
WATCHED_FILES=(
    /etc/ssh/sshd_config
    /etc/sudoers
    /root/.ssh/authorized_keys
)

_alert() {
    local msg="$1"
    logger -p security.warning -t secure-oss-light "[ALERT] ${msg}"
    {
        printf '\n'
        printf '┌──────────────────────────────────────────────────────────────┐\n'
        printf '│  ⚠  SECURE-OSS SECURITY ALERT                               │\n'
        printf '│  %-62s │\n' "${msg}"
        printf '│  journalctl -t secure-oss-light --since "-1h"               │\n'
        printf '└──────────────────────────────────────────────────────────────┘\n'
    } | wall --nobanner 2>/dev/null || wall 2>/dev/null || true
    while IFS= read -r uid; do
        [[ "${uid}" =~ ^[0-9]+$ ]] || continue
        local dbus_sock="/run/user/${uid}/bus"
        [[ -S "${dbus_sock}" ]] || continue
        local username
        username="$(id -nu "${uid}" 2>/dev/null)" || continue
        su -s /bin/bash "${username}" -- -c \
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${uid}/bus \
             notify-send \
               --urgency=critical --expire-time=0 \
               --app-name=secure-oss --icon=dialog-warning \
               'Security Alert' '${msg}'" \
            2>/dev/null || true
    done < <(loginctl list-users --no-legend 2>/dev/null | awk '{print $1}')
}

_check_file_changes() {
    for f in "${WATCHED_FILES[@]}"; do
        [[ -f "${f}" ]] || continue
        local hash_file="${STATE_DIR}/$(echo "${f}" | tr '/' '_').sha256"
        local current_hash
        current_hash="$(sha256sum "${f}" 2>/dev/null | awk '{print $1}')" || continue
        if [[ ! -f "${hash_file}" ]]; then
            # First run — record baseline silently
            echo "${current_hash}" > "${hash_file}"
            logger -p security.info -t secure-oss-light "Baseline recorded for ${f}"
        elif [[ "$(cat "${hash_file}")" != "${current_hash}" ]]; then
            _alert "File changed since last check: ${f} — verify this is an authorized change"
            echo "${current_hash}" > "${hash_file}"
        fi
    done

    # Check for new systemd service files dropped in /etc/systemd/system/
    local svc_list="${STATE_DIR}/systemd_services.txt"
    local current_svcs
    current_svcs="$(find /etc/systemd/system -maxdepth 1 \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) 2>/dev/null \
        | grep --invert-match 'secure-oss' | sort)" || current_svcs=""
    if [[ -f "${svc_list}" ]]; then
        local new_svcs
        new_svcs="$(comm -13 "${svc_list}" <(echo "${current_svcs}") 2>/dev/null || true)"
        if [[ -n "${new_svcs}" ]]; then
            while IFS= read -r svc; do
                _alert "New systemd unit: ${svc} — possible RMM/MDM agent install. Verify: systemctl status $(basename "${svc}")"
            done <<< "${new_svcs}"
        fi
    fi
    echo "${current_svcs}" > "${svc_list}"
}

_check_rmm_processes() {
    local found=0
    for proc in "${RMM_PROCS[@]}"; do
        if pgrep --ignore-case "${proc}" &>/dev/null; then
            _alert "Known RMM/remote-control process running: ${proc} — investigate: pgrep -la ${proc}"
            found=1
        fi
    done
    local rmm_svcs
    rmm_svcs="$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null \
        | awk '{print $1}' \
        | grep --ignore-case --extended-regexp \
            'teamview|anydesk|kaseya|splashtop|bomgar|pulseway|ninja|connectwise|screenconnect|zoho.assist|atera|dwagent|remotepc' \
        || true)"
    if [[ -n "${rmm_svcs}" ]]; then
        while IFS= read -r svc; do
            _alert "RMM/remote-control service running: ${svc} — investigate: systemctl status ${svc}"
            found=1
        done <<< "${rmm_svcs}"
    fi
    if [[ "${found}" -eq 0 ]]; then
        logger -p security.info -t secure-oss-light "Monitor poll: no RMM processes or unexpected file changes detected"
    fi
}

mkdir --parents "${STATE_DIR}"
_check_file_changes
_check_rmm_processes
MONITOR_EOF

    chmod 700 "${monitor_script}"
    restorecon -v "${monitor_script}" 2>/dev/null || true

    log "Writing ${monitor_svc}"
    cat > "${monitor_svc}" <<'SVC_EOF'
[Unit]
Description=secure-oss-light MDM/RMM monitor (one-shot poll)
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/secure-oss-light/monitor.sh
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secure-oss-light-monitor
SVC_EOF

    log "Writing ${monitor_timer}"
    cat > "${monitor_timer}" <<'TIMER_EOF'
[Unit]
Description=secure-oss-light MDM/RMM monitor (runs every 2 minutes)

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
Unit=secure-oss-light-monitor.service
AccuracySec=30s

[Install]
WantedBy=timers.target
TIMER_EOF

    systemctl daemon-reload
    systemctl enable --now secure-oss-light-monitor.timer
    # Run immediately to record the initial baseline checksums
    systemctl start secure-oss-light-monitor.service 2>/dev/null || true

    log "MDM/RMM monitoring active (polls every 2 minutes)."
    log "  All alerts : journalctl -t secure-oss-light --since '-24h'"
    log "  Trigger now: systemctl start secure-oss-light-monitor.service"

    mark_applied "monitor"
}

# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo -e "${_BOLD}=== Hardening Summary ===${_RESET}"
    echo ""

    local sections=(firewall services sysctl dhcp mac abrt cockpit amt monitor)
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
    echo "Verification commands:"
    echo "  Firewall : firewall-cmd --get-default-zone"
    echo "             firewall-cmd --list-all --zone=drop"
    echo "  Services : systemctl is-enabled avahi-daemon.service"
    echo "  Sysctl   : sysctl net.ipv4.conf.all.accept_redirects net.ipv4.tcp_syncookies"
    echo "  DHCP     : cat /etc/NetworkManager/conf.d/10-secure-oss-light-dhcp.conf"
    echo "  Cockpit  : systemctl is-enabled cockpit.socket"
    echo ""

    if [[ "${_FAILED}" -eq 1 ]]; then
        warn "One or more sections encountered errors. Review the output above."
        warn "Log file: ${LOG_FILE}"
    else
        log "All sections completed successfully."
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    mkdir --parents /var/log "${MARKER_DIR}"
    log "=== secure_oss-light harden.sh v${SCRIPT_VERSION} ==="

    require_root
    require_silverblue

    run_section "firewall" configure_firewall
    run_section "services" mask_services
    run_section "sysctl"   configure_sysctl
    run_section "dhcp"     suppress_dhcp_hostname
    run_section "mac"      configure_mac_randomization
    run_section "abrt"     mask_abrt
    run_section "cockpit"  mask_cockpit
    run_section "amt"      harden_amt
    run_section "monitor"  setup_monitoring

    print_summary

    if [[ "${_FAILED}" -ne 0 ]]; then
        exit 1
    fi
}

main "$@"
