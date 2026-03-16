#!/usr/bin/env bash
# harden.sh — System hardening for Fedora Workstation / KDE Plasma
#
# Platform  : Fedora Workstation (GNOME) or Fedora KDE Plasma (mutable)
# Purpose   : Applies kernel, network, service, and privacy hardening. Detects
#             the desktop environment and applies DE-specific settings automatically.
# Tested on : Fedora 41 Workstation, Fedora 41 KDE Plasma
# Requires  : root, provision.sh run first
#
# Usage:
#   sudo bash harden.sh [--dry-run] [--dns PROVIDER] [--skip SECTION]
#
# DNS providers (--dns):
#   quad9      Quad9 DoT — nonprofit, DNSSEC, no logging (default)
#   mullvad    Mullvad DoT — privacy-focused, Sweden
#   both       Quad9 primary, Mullvad secondary
#
# Sections (--skip, comma-separated):
#   kernel, sysctl, modules, selinux, firewall, ssh, dns, dhcp, mac,
#   usbguard, mdm, telemetry, services, de, coredumps, auth, amt, monitor

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

DNS_PROVIDER="quad9"
SKIP_SECTIONS=()

# DoT resolver definitions: IP|HOSTNAME|PORT
QUAD9_DOT="9.9.9.9|dns.quad9.net|853"
QUAD9_DOT_SECONDARY="149.112.112.112|dns.quad9.net|853"
MULLVAD_DOT="194.242.2.2|dns.mullvad.net|853"

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash harden.sh [OPTIONS]

Harden Fedora Workstation or KDE Plasma system security and privacy.

Options:
  --dns PROVIDER    DNS-over-TLS provider: quad9 | mullvad | both (default: quad9)
  --skip SECTIONS   Comma-separated list of sections to skip
  --dry-run         Show what would be done without making changes
  --help            Show this help
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
                DNS_PROVIDER="${2:?--dns requires a value}"
                shift 2 ;;
            --skip)
                IFS=',' read -ra SKIP_SECTIONS <<< "${2:?--skip requires a value}"
                shift 2 ;;
            *)
                die "Unknown argument: $1. Run with --help for usage." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Section 1: Kernel hardening arguments
#
# Applied via grubby to modify the kernel command line for all installed kernels.
# We apply a conservative desktop-appropriate subset — we avoid settings that
# break NVIDIA drivers, VirtualBox, or cut CPU performance significantly.
# ---------------------------------------------------------------------------

harden_kernel_args() {
    if is_applied "kernel-args"; then
        log "Kernel args already applied — skipping (reboot required for any changes to take effect)"
        return 0
    fi

    if ! command -v grubby &>/dev/null; then
        warn "grubby not found — skipping kernel argument hardening"
        return 0
    fi

    log "Applying kernel hardening arguments via grubby"
    log "These take effect on next reboot."

    local kargs=(
        # Page Table Isolation — mitigates Meltdown (CVE-2017-5754)
        "pti=on"

        # Spectre v2 mitigation
        "spectre_v2=on"

        # Speculative Store Bypass Disable
        "spec_store_bypass_disable=on"
        "ssbd=force-on"

        # IOMMU — protects against DMA attacks from PCIe devices
        # Covers both Intel VT-d and AMD-Vi
        "intel_iommu=on"
        "amd_iommu=on"
        "iommu=force"
        "iommu.passthrough=0"
        "iommu.strict=1"

        # Initialize memory on allocation and free — mitigates use-after-free
        # and uninitialized read vulnerabilities
        "init_on_alloc=1"
        "init_on_free=1"

        # Randomize kernel stack offset on syscall entry
        "randomize_kstack_offset=on"

        # Shuffle free memory page allocator lists — hardens ASLR
        "page_alloc.shuffle=1"

        # Do not trust bootloader or CPU for initial entropy seeding
        "random.trust_bootloader=off"
        "random.trust_cpu=off"

        # Restrict /proc/pid/mem access to ptrace-capable processes
        "proc_mem.force_override=ptrace"

        # Disable emergency shell in initramfs — prevents boot-time attack surface
        "rd.shell=0"

        # Suppress kernel log output to console — reduces information leakage
        # during boot (kernel log still available via dmesg with root)
        "loglevel=0"

        # Disable systemd emergency SSH auto-spawn (systemd >= 255)
        "systemd.ssh_auto=no"
    )

    run_cmd grubby --update-kernel=ALL --args="${kargs[*]}"

    mark_applied "kernel-args"
    log "Kernel args staged. Reboot to apply."
}

# ---------------------------------------------------------------------------
# Section 2: sysctl hardening
# ---------------------------------------------------------------------------

harden_sysctl() {
    local conf_src="${SCRIPT_DIR}/lib/sysctl-hardening.conf"
    local conf_dst="/etc/sysctl.d/90-secure-oss.conf"

    if [[ -f "${conf_dst}" ]]; then
        log "sysctl hardening already installed at ${conf_dst} — re-applying"
    fi

    if [[ ! -f "${conf_src}" ]]; then
        warn "sysctl config not found: ${conf_src} — skipping"
        return 1
    fi

    log "Installing sysctl hardening config to ${conf_dst}"

    if [[ "${DRY_RUN}" != "1" ]]; then
        cp "${conf_src}" "${conf_dst}"
        chmod 644 "${conf_dst}"
        restorecon -v "${conf_dst}" 2>/dev/null || true
        # Apply immediately without reboot
        sysctl --system --quiet
        log "sysctl settings applied to running kernel"
    else
        echo "[DRY RUN] Would copy ${conf_src} to ${conf_dst}"
        echo "[DRY RUN] Would run: sysctl --system"
    fi

    mark_applied "sysctl"
}

# ---------------------------------------------------------------------------
# Section 3: Kernel module blacklisting
# ---------------------------------------------------------------------------

harden_modules() {
    local conf_src="${SCRIPT_DIR}/lib/modprobe-blacklist.conf"
    local conf_dst="/etc/modprobe.d/secure-oss-blacklist.conf"

    if [[ ! -f "${conf_src}" ]]; then
        warn "Module blacklist not found: ${conf_src} — skipping"
        return 1
    fi

    log "Installing kernel module blacklist to ${conf_dst}"

    if [[ "${DRY_RUN}" != "1" ]]; then
        cp "${conf_src}" "${conf_dst}"
        chmod 644 "${conf_dst}"
        restorecon -v "${conf_dst}" 2>/dev/null || true
        # Regenerate initramfs to bake blacklist into early boot
        dracut --force --quiet 2>/dev/null || \
            warn "dracut not available — reboot required for module blacklist to take full effect"
    else
        echo "[DRY RUN] Would copy ${conf_src} to ${conf_dst}"
        echo "[DRY RUN] Would run: dracut --force"
    fi

    mark_applied "modules"
}

# ---------------------------------------------------------------------------
# Section 4: SELinux enforcement
# ---------------------------------------------------------------------------

harden_selinux() {
    local selinux_conf="/etc/selinux/config"

    log "Checking SELinux enforcement status"

    local current_mode
    current_mode="$(getenforce 2>/dev/null || echo "unknown")"

    if [[ "${current_mode}" == "Enforcing" ]]; then
        log "SELinux is already Enforcing — verifying config file"
    else
        warn "SELinux is currently: ${current_mode} — setting to Enforcing"
        run_cmd setenforce 1 2>/dev/null || warn "setenforce failed (may need reboot)"
    fi

    # Ensure the config file sets SELINUX=enforcing for persistence across reboots
    if [[ -f "${selinux_conf}" ]]; then
        if grep --quiet "^SELINUX=enforcing" "${selinux_conf}"; then
            log "SELinux config already set to enforcing"
        else
            if [[ "${DRY_RUN}" != "1" ]]; then
                sed --in-place 's/^SELINUX=.*/SELINUX=enforcing/' "${selinux_conf}"
                log "SELinux config updated to enforcing"
            else
                echo "[DRY RUN] Would set SELINUX=enforcing in ${selinux_conf}"
            fi
        fi
    fi

    mark_applied "selinux"
}

# ---------------------------------------------------------------------------
# Section 5: Firewall (firewalld)
#
# Sets the default zone to a fully closed profile: no inbound ports, no
# services. Outbound traffic is unrestricted (firewalld default).
# ---------------------------------------------------------------------------

harden_firewall() {
    if ! command -v firewall-cmd &>/dev/null; then
        warn "firewall-cmd not found — installing firewalld"
        run_cmd dnf install --assumeyes firewalld
    fi

    log "Configuring firewalld — default-deny inbound"

    # Ensure firewalld is running
    run_cmd systemctl enable --now firewalld.service

    # Get current default zone
    local default_zone
    default_zone="$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")"
    log "Default zone: ${default_zone}"

    # Remove all services and ports from the default zone
    # This makes all inbound connections refused by default
    local services
    services="$(firewall-cmd --zone="${default_zone}" --list-services 2>/dev/null || echo "")"
    for svc in ${services}; do
        log "Removing service: ${svc}"
        run_cmd firewall-cmd --zone="${default_zone}" --remove-service="${svc}" --permanent
    done

    local ports
    ports="$(firewall-cmd --zone="${default_zone}" --list-ports 2>/dev/null || echo "")"
    for port in ${ports}; do
        log "Removing port: ${port}"
        run_cmd firewall-cmd --zone="${default_zone}" --remove-port="${port}" --permanent
    done

    # Reload to apply permanent changes
    run_cmd firewall-cmd --reload

    log "Firewall configured: default-deny inbound on zone '${default_zone}'"
    log "To allow a service (e.g., SSH): firewall-cmd --add-service=ssh --permanent && firewall-cmd --reload"

    mark_applied "firewall"
}

# ---------------------------------------------------------------------------
# Section 6: SSH hardening
#
# If sshd is installed, tighten its configuration. If it is not needed,
# disable it entirely. We default to disabling it for desktop systems.
# ---------------------------------------------------------------------------

harden_ssh() {
    if ! rpm --query openssh-server &>/dev/null; then
        log "openssh-server not installed — skipping SSH hardening"
        mark_applied "ssh"
        return 0
    fi

    local sshd_conf="/etc/ssh/sshd_config"
    local drop_in="/etc/ssh/sshd_config.d/90-secure-oss.conf"

    log "Hardening SSH configuration"

    # For a desktop, disable sshd entirely unless the user explicitly needs it
    if systemctl is-enabled sshd.service &>/dev/null \
        && ! systemctl is-enabled sshd.service 2>/dev/null | grep --quiet "enabled"; then
        log "sshd is not enabled — masking to prevent accidental start"
        run_cmd systemctl mask sshd.service
        mark_applied "ssh"
        return 0
    fi

    # If SSH is actively enabled (user chose to keep it), harden the config
    log "sshd is enabled — applying hardened configuration drop-in at ${drop_in}"

    write_file "${drop_in}" "# secure_oss SSH hardening drop-in
# Applied by harden.sh — do not edit manually

# Disable root login over SSH
PermitRootLogin no

# Disable password authentication — require key-based auth
PasswordAuthentication no
KbdInteractiveAuthentication no

# Disable PAM challenge/response (belt-and-suspenders with above)
ChallengeResponseAuthentication no

# Disable X11 forwarding — attack surface reduction
X11Forwarding no

# Disable agent forwarding — prevents credential theft on compromised hosts
AllowAgentForwarding no

# Disable TCP forwarding — prevents tunnel abuse
AllowTcpForwarding no

# Use privilege separation (should be default but be explicit)
UsePrivilegeSeparation sandbox

# Limit authentication attempts
MaxAuthTries 3

# Disconnect idle sessions after 10 minutes
ClientAliveInterval 300
ClientAliveCountMax 2

# Only accept strong key exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Log at INFO level (default) for auditability
LogLevel INFO"

    run_cmd systemctl restart sshd.service

    mark_applied "ssh"
}

# ---------------------------------------------------------------------------
# Section 7: Encrypted DNS via systemd-resolved
#
# Fedora (mutable) uses systemd-resolved by default (not dnsconfd like
# secureblue). We configure it to use DNS-over-TLS with the selected provider.
# ---------------------------------------------------------------------------

configure_dns() {
    if is_applied "dns"; then
        log "DNS already configured — skipping"
        return 0
    fi

    local resolvers=()
    case "${DNS_PROVIDER}" in
        quad9)   resolvers=("${QUAD9_DOT}" "${QUAD9_DOT_SECONDARY}") ;;
        mullvad) resolvers=("${MULLVAD_DOT}") ;;
        both)    resolvers=("${QUAD9_DOT}" "${MULLVAD_DOT}" "${QUAD9_DOT_SECONDARY}") ;;
        *)       die "Unknown DNS provider: ${DNS_PROVIDER}" ;;
    esac

    log "Configuring DNS-over-TLS via systemd-resolved (provider: ${DNS_PROVIDER})"

    # Build space-separated DNS server list for resolved.conf
    local dns_servers=()
    local dns_domains=()
    for resolver in "${resolvers[@]}"; do
        local ip hostname port
        IFS='|' read -r ip hostname port <<< "${resolver}"
        # resolved.conf accepts: IP#hostname for TLS SNI
        dns_servers+=("${ip}#${hostname}")
    done

    write_file "/etc/systemd/resolved.conf.d/90-secure-oss-dot.conf" \
"# secure_oss: DNS-over-TLS configuration
# Configured by harden.sh
[Resolve]
DNS=${dns_servers[*]}
DNSOverTLS=yes
DNSSEC=yes
DNSStubListener=yes"

    run_cmd systemctl restart systemd-resolved.service

    # Verify DNS is working
    if [[ "${DRY_RUN}" != "1" ]]; then
        if resolvectl query quad9.net &>/dev/null; then
            log "DNS resolution verified successfully"
        else
            warn "DNS verification failed — check /etc/systemd/resolved.conf.d/90-secure-oss-dot.conf"
        fi
    fi

    mark_applied "dns"
}

# ---------------------------------------------------------------------------
# Section 8: DHCP hostname suppression
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
# Hostname leakage allows network operators to identify and track devices.
ipv4.dhcp-send-hostname=false
ipv6.dhcp-send-hostname=false"

    warn_if_ssh_will_disconnect
    run_cmd nmcli general reload conf

    mark_applied "dhcp"
}

# ---------------------------------------------------------------------------
# Section 9: MAC address randomization (per-connection)
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
# A new MAC address is generated on every connection attempt.
ethernet.cloned-mac-address=random
wifi.cloned-mac-address=random

[device]
wifi.scan-rand-mac-address=yes"

    warn_if_ssh_will_disconnect
    run_cmd nmcli general reload conf

    mark_applied "mac"
}

# ---------------------------------------------------------------------------
# Section 10: USBGuard
# ---------------------------------------------------------------------------

setup_usbguard() {
    if [[ -f /etc/usbguard/rules.conf ]] \
        && systemctl is-enabled usbguard.service &>/dev/null; then
        log "USBGuard already configured and enabled — skipping"
        return 0
    fi

    if ! command -v usbguard &>/dev/null; then
        warn "usbguard not found — run provision.sh first"
        return 1
    fi

    # Safety check: require at least one HID input device in policy
    local hid_count
    hid_count="$(usbguard list-devices 2>/dev/null \
        | grep --count --ignore-case "HID\|keyboard\|mouse" || echo "0")"

    if [[ "${hid_count}" -eq 0 ]]; then
        warn "No HID (keyboard/mouse) USB devices detected."
        warn "Enabling USBGuard without input devices could lock you out."
        warn "Connect a USB keyboard/mouse and re-run, or skip with --skip usbguard"
        return 1
    fi

    log "Detected ${hid_count} HID device(s) — safe to generate USBGuard policy"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would generate USBGuard policy:"
        usbguard generate-policy 2>/dev/null || true
        return 0
    fi

    mkdir --parents /etc/usbguard /var/log/usbguard
    restorecon -vR /etc/usbguard /var/log/usbguard 2>/dev/null || true

    usbguard generate-policy > /etc/usbguard/rules.conf
    chmod 600 /etc/usbguard/rules.conf
    restorecon -v /etc/usbguard/rules.conf 2>/dev/null || true

    systemctl enable --now usbguard.service
    log "USBGuard enabled."

    mark_applied "usbguard"
}

# ---------------------------------------------------------------------------
# Section 11: MDM domain blocking
# ---------------------------------------------------------------------------

block_mdm_domains() {
    local blocklist="${SCRIPT_DIR}/lib/hosts-mdm.txt"
    [[ -f "${blocklist}" ]] || { warn "MDM blocklist not found: ${blocklist}"; return 1; }

    log "Applying MDM domain blocklist to /etc/hosts"
    _apply_hosts_blocklist "${blocklist}" "MDM"
    mark_applied "mdm"
}

# ---------------------------------------------------------------------------
# Section 12: Telemetry domain blocking
# ---------------------------------------------------------------------------

block_telemetry_domains() {
    local blocklist="${SCRIPT_DIR}/lib/hosts-telemetry.txt"
    [[ -f "${blocklist}" ]] || { warn "Telemetry blocklist not found: ${blocklist}"; return 1; }

    log "Applying telemetry domain blocklist to /etc/hosts"
    _apply_hosts_blocklist "${blocklist}" "TELEMETRY"
    mark_applied "telemetry"
}

_apply_hosts_blocklist() {
    local blocklist="$1"
    local label="$2"
    local begin_marker="### BEGIN secure_oss ${label} BLOCK — DO NOT EDIT ###"
    local end_marker="### END secure_oss ${label} BLOCK ###"

    local entries
    entries="$(grep --extended-regexp --invert-match '^[[:space:]]*#|^[[:space:]]*$' \
        "${blocklist}" | awk '{printf "0.0.0.0  %s\n", $1}')"

    local count
    count="$(echo "${entries}" | wc --lines)"
    log "Blocking ${count} domains from ${blocklist}"

    append_block "/etc/hosts" "${begin_marker}" "${end_marker}" "${entries}"
}

# ---------------------------------------------------------------------------
# Section 13: System service hardening
# Masks services that are attack surfaces on a desktop system.
# ---------------------------------------------------------------------------

harden_services() {
    log "Hardening system services"

    # ABRT — crash reporter that sends data to Red Hat
    local abrt_units=(
        abrt.service abrtd.service abrt-ccpp.service abrt-oops.service
        abrt-journal-core.service abrt-pstoreoops.service abrt-vmcore.service
        abrt-xorg.service abrt-dump-journal-core.service
    )
    for unit in "${abrt_units[@]}"; do
        if systemctl cat "${unit}" &>/dev/null; then
            if ! systemctl is-enabled "${unit}" 2>/dev/null | grep --quiet "masked"; then
                run_cmd systemctl mask "${unit}"
            fi
        fi
    done

    # Avahi — mDNS/DNS-SD zero-config networking. Leaks hostname on LAN.
    for avahi_unit in avahi-daemon.service avahi-daemon.socket; do
        if systemctl cat "${avahi_unit}" &>/dev/null; then
            if ! systemctl is-enabled "${avahi_unit}" 2>/dev/null | grep --quiet "masked"; then
                log "Masking ${avahi_unit} (mDNS — leaks hostname on LAN)"
                run_cmd systemctl mask "${avahi_unit}"
            fi
        fi
    done

    # Cockpit — web-based admin console, exposes HTTP server
    if systemctl cat cockpit.socket &>/dev/null; then
        if ! systemctl is-enabled cockpit.socket 2>/dev/null | grep --quiet "masked"; then
            log "Masking cockpit.socket (web admin console)"
            run_cmd systemctl mask cockpit.socket
        fi
    fi

    mark_applied "services"
}

# ---------------------------------------------------------------------------
# Section 14: Desktop environment specific hardening
# ---------------------------------------------------------------------------

harden_de() {
    detect_desktop_environment

    case "${DE}" in
        gnome)
            # shellcheck source=lib/gnome.sh
            source "${SCRIPT_DIR}/lib/gnome.sh"
            harden_gnome
            ;;
        kde)
            # shellcheck source=lib/kde.sh
            source "${SCRIPT_DIR}/lib/kde.sh"
            harden_kde
            ;;
        unknown)
            warn "Unknown desktop environment — skipping DE-specific hardening"
            return 0
            ;;
    esac

    mark_applied "de-${DE}"
}

# ---------------------------------------------------------------------------
# Section 15: Core dump disabling
# ---------------------------------------------------------------------------

harden_coredumps() {
    log "Disabling core dumps"

    # systemd coredump handler
    write_file "/etc/systemd/coredump.conf.d/90-secure-oss.conf" \
"[Coredump]
# Disable core dump storage — prevents sensitive memory from being written to disk
Storage=none
ProcessSizeMax=0"

    # PAM limits fallback
    write_file "/etc/security/limits.d/90-secure-oss-coredump.conf" \
"# Disable core dumps via PAM limits
* hard core 0
* soft core 0"

    # sysctl is handled by lib/sysctl-hardening.conf (kernel.core_pattern)

    run_cmd systemctl daemon-reload

    mark_applied "coredumps"
}

# ---------------------------------------------------------------------------
# Section 16: Authentication hardening
# ---------------------------------------------------------------------------

harden_auth() {
    if is_applied "auth"; then
        log "Auth hardening already applied — skipping"
        return 0
    fi

    log "Hardening authentication settings"

    # faillock — account lockout after repeated failed logins
    write_file "/etc/security/faillock.conf" \
"# secure_oss: account lockout policy
# Lock account after 10 failed attempts (lenient desktop default)
# Use 50 for high-security environments
deny = 10
# Unlock after 15 minutes (900 seconds)
unlock_time = 900
# Also lock the root account
even_deny_root = true
# Count failures across all authentication sources
audit = true"

    # pwquality — password complexity requirements
    write_file "/etc/security/pwquality.conf" \
"# secure_oss: password quality requirements
# Minimum 12 characters
minlen = 12
# Require at least 1 digit
dcredit = -1
# Require at least 1 uppercase letter
ucredit = -1
# Require at least 1 lowercase letter
lcredit = -1
# Require at least 1 special character
ocredit = -1
# Check against dictionary words
dictcheck = 1
# Enforce for root too
enforce_for_root"

    mark_applied "auth"
}

# ---------------------------------------------------------------------------
# Section 17: Intel ME/AMT hardening
#
# Intel Management Engine (ME) is a separate microcontroller that runs
# independently of the OS at Ring -3. AMT (Active Management Technology)
# is an ME feature that provides out-of-band remote management (KVM, power
# control, network access) reachable even when the OS is off.
#
# ┌─────────────────────────────────────────────────────────────────────┐
# │  HARD LIMIT — what OS-level hardening CANNOT do:                   │
# │                                                                     │
# │  In shared-NIC mode, AMT intercepts TCP/UDP packets on its ports    │
# │  BEFORE the kernel network stack sees them. iptables / firewalld   │
# │  rules DO NOT block network-level AMT access. The firewall is      │
# │  bypassed at the hardware level.                                   │
# │                                                                     │
# │  Primary mitigation: disable AMT/ME in BIOS/MEBx, then apply      │
# │  Intel firmware updates listed in INTEL-SA security advisories.    │
# └─────────────────────────────────────────────────────────────────────┘
#
# What this section DOES achieve:
#
#   1. Blacklists mei_me and mei_wdt kernel modules via modprobe.d
#      → Severs the kernel's communication channel to the ME firmware
#      → Reduces the OS-visible attack surface of the MEI interface
#      → Requires reboot to take full effect
#      NOTE: Trade-off — may affect Intel SGX, Intel PTT (Platform Trust
#      Technology), and some UEFI Secure Boot workflows if those features
#      are needed. Use --skip amt if those are required.
#
#   2. Checks for AMT port listeners in the current OS network stack
#      → Absence does NOT confirm AMT is disabled (see hard limit above)
#      → Presence confirms AMT IS active and may be accessible
#
#   3. Deploys a periodic monitor for AMT indicators:
#      → Alerts if mei_me module is (re-)loaded after being blacklisted
#      → Alerts if AMT ports appear in the OS network stack
#      → Hooks into the existing RMM scan timer if the monitor section
#        was applied; otherwise creates a standalone 15-minute timer
#
# Verification:
#   cat /etc/modprobe.d/secure-oss-amt.conf
#   lsmod | grep mei_me    (should return nothing after reboot)
#   ss -tlnp | grep -E '16992|16993'
#   journalctl -t secure-oss --since '-24h' | grep -i amt
# ---------------------------------------------------------------------------

harden_amt() {
    # Detect Intel ME device
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
    local amt_check_script="/usr/local/lib/secure-oss/amt-check.sh"
    local scan_dropin_dir="/etc/systemd/system/secure-oss-monitor-scan.service.d"

    # --- 1. Blacklist MEI kernel modules ---

    write_file "${amt_modprobe}" "# secure_oss: Intel Management Engine kernel module restrictions
# Applied by harden.sh (amt section).
# Reboot required for blacklist to take full effect.
#
# mei_me  — OS-to-ME communication driver (HECI/MEI interface).
#           Blacklisting severs the kernel's channel to ME firmware.
#           ME hardware continues running independently at Ring -3.
#           NOTE: may affect Intel SGX, Intel PTT, and some UEFI
#           Secure Boot workflows. Remove this file if needed.
#
# mei_wdt — ME-driven hardware watchdog timer.
#           Not required for normal desktop/server operation.
blacklist mei_me
blacklist mei_wdt
install mei_me /bin/false
install mei_wdt /bin/false"

    if [[ "${DRY_RUN}" != "1" ]]; then
        # Attempt immediate unload — may fail if other modules depend on mei_me;
        # that is non-fatal, the blacklist takes effect on next reboot.
        rmmod mei_wdt 2>/dev/null || true
        if ! lsmod 2>/dev/null | awk 'NR>1 {print $4}' | tr ',' '\n' | grep --quiet '^mei_me$'; then
            rmmod mei_me 2>/dev/null || true
        else
            warn "mei_me has dependent modules — it will be blocked on next reboot"
        fi
    fi

    # --- 2. AMT provisioning check ---

    if command -v mei-amt-check &>/dev/null; then
        log "Running mei-amt-check..."
        local amt_output
        amt_output="$(mei-amt-check 2>&1 || true)"
        log "AMT status: ${amt_output}"
        if echo "${amt_output}" | grep --quiet --ignore-case 'provisioned\|enabled'; then
            warn "AMT IS PROVISIONED — remote management may be active."
            warn "Disable AMT in BIOS/MEBx before treating this system as secure."
        fi
    else
        log "mei-amt-check not installed — using port listener check as fallback"
        log "(Install mei-amt-check for definitive provisioning state: https://github.com/mjg59/mei-amt-check)"
        # AMT in shared-NIC mode intercepts packets before the OS, so these ports
        # usually do NOT appear in ss output. Their presence here means AMT is
        # accessible via a user-space proxy (unusual) or dedicated NIC path.
        if [[ "${DRY_RUN}" != "1" ]]; then
            local amt_listeners
            amt_listeners="$(ss --tcp --listening --numeric 2>/dev/null \
                | awk '{print $4}' \
                | grep --extended-regexp ':16992$|:16993$|:16994$|:16995$|:623$|:664$' || true)"
            if [[ -n "${amt_listeners}" ]]; then
                warn "AMT management ports are listening in the OS network stack: ${amt_listeners}"
                warn "AMT is provisioned and active. Disable in BIOS/MEBx immediately."
            else
                log "AMT ports not visible in OS network stack."
                log "This is expected in shared-NIC mode — it does NOT confirm AMT is off."
                log "Verify AMT state in BIOS/MEBx or by installing mei-amt-check."
            fi
        fi
    fi

    # --- 3. Deploy AMT-specific monitor ---

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would write: ${amt_check_script}"
        echo "[DRY RUN] Would hook into scan timer or create standalone timer"
    else
        mkdir --parents /usr/local/lib/secure-oss

        cat > "${amt_check_script}" <<'AMT_EOF'
#!/usr/bin/env bash
# secure-oss AMT monitor — detects ME kernel interface activation
# Deployed by harden.sh (amt section). Runs via the RMM scan timer.
set -uo pipefail

_amt_alert() {
    local msg="$1"
    logger -p security.warning -t secure-oss "[AMT ALERT] ${msg}"
    {
        printf '\n'
        printf '┌──────────────────────────────────────────────────────────────┐\n'
        printf '│  ⚠  SECURE-OSS AMT/ME ALERT                                 │\n'
        printf '│  %-62s │\n' "${msg}"
        printf '│  journalctl -t secure-oss --since "-1h"                     │\n'
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
# This is the primary OS-observable indicator that the ME kernel interface
# has been restored — either by a reboot without the blacklist or by an
# explicit modprobe call (which requires root, but is worth detecting).
if lsmod 2>/dev/null | grep --quiet '^mei_me'; then
    _amt_alert "Intel MEI module (mei_me) is loaded — ME kernel interface is active. Blacklisted by secure-oss; verify /etc/modprobe.d/secure-oss-amt.conf and reboot."
fi

# Check 2: AMT ports visible in OS network stack
# In shared-NIC mode these ports are normally invisible to the OS.
# Their appearance here indicates either a user-space AMT proxy, a
# dedicated management NIC, or unusual AMT configuration.
amt_listeners="$(ss --tcp --listening --numeric 2>/dev/null \
    | awk '{print $4}' \
    | grep --extended-regexp ':16992$|:16993$|:16994$|:16995$|:623$|:664$' || true)"
if [[ -n "${amt_listeners}" ]]; then
    _amt_alert "AMT management port visible in OS network stack: ${amt_listeners} — AMT is provisioned and accessible via the OS path"
fi

logger -p security.info -t secure-oss "AMT check complete"
AMT_EOF

        chmod 700 "${amt_check_script}"
        restorecon -v "${amt_check_script}" 2>/dev/null || true

        # Hook into the existing RMM scan service if the monitor section was applied;
        # otherwise create a standalone timer.
        if systemctl cat secure-oss-monitor-scan.service &>/dev/null; then
            mkdir --parents "${scan_dropin_dir}"
            cat > "${scan_dropin_dir}/50-amt.conf" <<'DROPIN_EOF'
# secure-oss amt section: extend RMM scan service with AMT-specific checks
[Service]
ExecStart=/usr/local/lib/secure-oss/amt-check.sh
DROPIN_EOF
            systemctl daemon-reload
            log "AMT check added to existing RMM scan timer via service drop-in"
        else
            # monitor section not applied — create standalone timer
            cat > /etc/systemd/system/secure-oss-amt-check.service <<'SVC_EOF'
[Unit]
Description=secure-oss Intel AMT monitor (one-shot)
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/secure-oss/amt-check.sh
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secure-oss-monitor
SVC_EOF
            cat > /etc/systemd/system/secure-oss-amt-check.timer <<'TIMER_EOF'
[Unit]
Description=secure-oss Intel AMT monitor timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Unit=secure-oss-amt-check.service
AccuracySec=1min

[Install]
WantedBy=timers.target
TIMER_EOF
            systemctl daemon-reload
            systemctl enable --now secure-oss-amt-check.timer
            log "Standalone AMT check timer created (runs every 15 minutes)"
        fi
    fi

    # --- 4. Inform about primary (non-scriptable) mitigations ---
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
    reboot_notice "mei_me module blacklist takes effect on next reboot"

    mark_applied "amt"
}

# ---------------------------------------------------------------------------
# Section 18: MDM/RMM intrusion monitoring
#
# Deploys a background monitor that watches for signs of MDM enrollment or
# remote management tool installation and sends active alerts via:
#   - wall       — broadcast to all connected terminals immediately
#   - logger     — writes to the systemd journal (persistent, survives reboots)
#   - notify-send — desktop notification to logged-in Wayland/X11 sessions
#
# Two components:
#   1. secure-oss-monitor.service  — continuous inotifywait watch on key
#      filesystem paths (systemd unit dir, SSH config, sudoers, cron)
#   2. secure-oss-monitor-scan.timer — periodic (every 5 min) scan for
#      known RMM/remote-control process names
#
# Watched paths:
#   /etc/systemd/system/         New .service/.timer files — possible RMM agent
#   /etc/ssh/                    sshd_config changes — possible backdoor config
#   /etc/sudoers{,.d/}           Privilege escalation changes
#   /root/.ssh/authorized_keys   Root SSH backdoor key
#   /etc/cron.d/                 New cron persistence jobs
#
# Detected RMM tools:
#   TeamViewer, AnyDesk, Datto RMM, Kaseya, Splashtop, BeyondTrust/Bomgar,
#   NinjaOne, ConnectWise, ScreenConnect, GoTo Resolve, Zoho Assist, Atera
#
# Requirements: inotify-tools (installed by this section if missing)
#
# Verification:
#   systemctl status secure-oss-monitor.service
#   systemctl status secure-oss-monitor-scan.timer
#   journalctl -t secure-oss --since '-24h'
# ---------------------------------------------------------------------------

setup_monitoring() {
    local monitor_script="/usr/local/lib/secure-oss/monitor.sh"
    local watch_svc="/etc/systemd/system/secure-oss-monitor.service"
    local scan_svc="/etc/systemd/system/secure-oss-monitor-scan.service"
    local scan_timer="/etc/systemd/system/secure-oss-monitor-scan.timer"

    if is_applied "monitor"; then
        log "MDM/RMM monitoring already configured — skipping"
        return 0
    fi

    log "Setting up MDM/RMM intrusion monitoring"

    # Install inotify-tools if not present
    if ! command -v inotifywait &>/dev/null; then
        log "Installing inotify-tools (required for filesystem event monitoring)"
        run_cmd dnf install --assumeyes inotify-tools
    fi

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would write: ${monitor_script}"
        echo "[DRY RUN] Would write: ${watch_svc}"
        echo "[DRY RUN] Would write: ${scan_svc}"
        echo "[DRY RUN] Would write: ${scan_timer}"
        echo "[DRY RUN] Would enable: secure-oss-monitor.service secure-oss-monitor-scan.timer"
        return 0
    fi

    mkdir --parents /usr/local/lib/secure-oss
    restorecon -vR /usr/local/lib/secure-oss 2>/dev/null || true

    log "Writing ${monitor_script}"
    cat > "${monitor_script}" <<'MONITOR_EOF'
#!/usr/bin/env bash
# secure-oss-monitor — MDM/RMM intrusion detection
# Managed by harden.sh — do not edit manually.
# Usage: monitor.sh [watch|scan]
set -uo pipefail

# Known RMM/remote-management process names (case-insensitive match).
# This list covers common commercial RMM tools but is not exhaustive —
# new agents and rebranded tools appear regularly. Extend this list to
# match any additional tools relevant to your environment.
RMM_PROCS=(
    teamviewerd        # TeamViewer daemon
    anydesk            # AnyDesk
    dwagent            # Datto RMM agent
    dcsystemservice    # Datto RMM secondary service
    kaseya             # Kaseya VSA
    agentmon           # Kaseya AgentMon
    splashtop_streamer # Splashtop remote desktop
    bomgar-scc         # BeyondTrust / Bomgar
    pulsewaymgr        # Pulseway
    ninjaone           # NinjaOne (NinjaRMM)
    ninjarmmagent      # NinjaRMM alternate name
    connectwise        # ConnectWise Control
    cwautomate         # ConnectWise Automate
    screenconnect      # ScreenConnect
    remotepc           # RemotePC
    goto-agent         # GoTo Resolve
    zohoassist         # Zoho Assist
    atera              # Atera
)

_alert() {
    local msg="$1"
    # 1. Persistent journal entry (journalctl -t secure-oss)
    logger -p security.warning -t secure-oss "[ALERT] ${msg}"
    # 2. Broadcast to all terminals immediately
    {
        printf '\n'
        printf '┌──────────────────────────────────────────────────────────────┐\n'
        printf '│  ⚠  SECURE-OSS SECURITY ALERT                               │\n'
        printf '│  %-62s │\n' "${msg}"
        printf '│  journalctl -t secure-oss --since "-1h"                     │\n'
        printf '└──────────────────────────────────────────────────────────────┘\n'
    } | wall --nobanner 2>/dev/null || wall 2>/dev/null || true
    # 3. Desktop notification to all active Wayland/X11 sessions
    while IFS= read -r uid; do
        [[ "${uid}" =~ ^[0-9]+$ ]] || continue
        local dbus_sock="/run/user/${uid}/bus"
        [[ -S "${dbus_sock}" ]] || continue
        local username
        username="$(id -nu "${uid}" 2>/dev/null)" || continue
        su -s /bin/bash "${username}" -- -c \
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${uid}/bus \
             notify-send \
               --urgency=critical \
               --expire-time=0 \
               --app-name=secure-oss \
               --icon=dialog-warning \
               'Security Alert' \
               '${msg}'" \
            2>/dev/null || true
    done < <(loginctl list-users --no-legend 2>/dev/null | awk '{print $1}')
}

_do_watch() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] secure-oss-monitor: filesystem watch started" >&2
    # Ensure all watched directories exist
    for d in /etc/sudoers.d /etc/cron.d /root/.ssh; do
        [[ -d "${d}" ]] || mkdir --parents "${d}"
    done
    inotifywait \
        --monitor --recursive \
        --event create,modify,moved_to \
        --quiet \
        --format '%w%f|%e' \
        /etc/systemd/system \
        /etc/ssh \
        /etc/sudoers \
        /etc/sudoers.d \
        /root/.ssh \
        /etc/cron.d \
        2>/dev/null | \
    while IFS='|' read -r path event; do
        case "${path}" in
            /etc/systemd/system/*.service|\
            /etc/systemd/system/*.timer|\
            /etc/systemd/system/*.socket)
                [[ "${event}" == *CREATE* || "${event}" == *MOVED_TO* ]] || continue
                [[ "${path}" == *secure-oss* ]] && continue
                _alert "New systemd unit: ${path} — possible RMM/MDM agent install. Verify: systemctl status $(basename "${path}")"
                ;;
            /etc/ssh/sshd_config|\
            /etc/ssh/sshd_config.d/*)
                _alert "SSH daemon config modified: ${path} — verify no unauthorized changes: sshd -T | grep -i permit"
                ;;
            /root/.ssh/authorized_keys)
                _alert "Root SSH authorized_keys modified — verify no unauthorized keys: cat /root/.ssh/authorized_keys"
                ;;
            /etc/sudoers|\
            /etc/sudoers.d/*)
                [[ "${path}" == *secure-oss* ]] && continue
                _alert "sudoers modified: ${path} — verify no unauthorized privilege escalation: visudo -c && cat ${path}"
                ;;
            /etc/cron.d/*)
                [[ "${event}" == *CREATE* || "${event}" == *MOVED_TO* ]] || continue
                [[ "${path}" == *secure-oss* ]] && continue
                _alert "New cron job: ${path} — verify not a persistence mechanism: cat ${path}"
                ;;
        esac
    done
}

_do_scan() {
    local found=0
    for proc in "${RMM_PROCS[@]}"; do
        if pgrep --ignore-case "${proc}" &>/dev/null; then
            _alert "Known RMM/remote-control process running: ${proc} — investigate: pgrep -la ${proc}"
            found=1
        fi
    done
    # Also match running systemd services by name
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
        logger -p security.info -t secure-oss "RMM scan complete: no known remote management processes detected"
    fi
}

case "${1:-watch}" in
    watch) _do_watch ;;
    scan)  _do_scan  ;;
    *)     echo "Usage: $0 [watch|scan]"; exit 1 ;;
esac
MONITOR_EOF

    chmod 700 "${monitor_script}"
    restorecon -v "${monitor_script}" 2>/dev/null || true

    log "Writing ${watch_svc}"
    cat > "${watch_svc}" <<'SVC_EOF'
[Unit]
Description=secure-oss MDM/RMM filesystem monitor
Documentation=man:inotifywait(1)
After=multi-user.target
Wants=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/lib/secure-oss/monitor.sh watch
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secure-oss-monitor

[Install]
WantedBy=multi-user.target
SVC_EOF

    log "Writing ${scan_svc}"
    cat > "${scan_svc}" <<'SVC_EOF'
[Unit]
Description=secure-oss RMM process scan (one-shot)
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/secure-oss/monitor.sh scan
StandardOutput=journal
StandardError=journal
SyslogIdentifier=secure-oss-monitor
SVC_EOF

    log "Writing ${scan_timer}"
    cat > "${scan_timer}" <<'TIMER_EOF'
[Unit]
Description=secure-oss periodic RMM process scan

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
Unit=secure-oss-monitor-scan.service
AccuracySec=30s

[Install]
WantedBy=timers.target
TIMER_EOF

    systemctl daemon-reload
    systemctl enable --now secure-oss-monitor.service
    systemctl enable --now secure-oss-monitor-scan.timer

    log "MDM/RMM monitoring active."
    log "  Filesystem alerts : journalctl -u secure-oss-monitor -f"
    log "  All alerts        : journalctl -t secure-oss --since '-24h'"
    log "  Manual RMM scan   : systemctl start secure-oss-monitor-scan.service"

    mark_applied "monitor"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo -e "${_BOLD}=== Hardening Summary ===${_RESET}"
    echo ""

    local sections=(
        kernel-args sysctl modules selinux firewall ssh dns
        dhcp mac usbguard mdm telemetry services coredumps auth amt monitor
    )
    for section in "${sections[@]}"; do
        if is_applied "${section}"; then
            echo -e "  ${_GREEN}✓${_RESET} ${section}"
        elif should_skip "${section}"; then
            echo -e "  ${_YELLOW}−${_RESET} ${section} (skipped)"
        else
            echo -e "  ${_RED}✗${_RESET} ${section} (not applied or failed)"
        fi
    done

    # DE section uses a different marker name
    local de_applied=0
    for de in gnome kde unknown; do
        is_applied "de-${de}" && de_applied=1 && break
    done
    if [[ "${de_applied}" -eq 1 ]]; then
        echo -e "  ${_GREEN}✓${_RESET} de (${DE})"
    elif should_skip "de"; then
        echo -e "  ${_YELLOW}−${_RESET} de (skipped)"
    else
        echo -e "  ${_RED}✗${_RESET} de (not applied)"
    fi

    echo ""
    reboot_notice "Kernel args and module blacklist require a reboot"
    echo ""
    echo "Optional extras:"
    echo "  sudo bash optional/disable-webcam.sh"
    echo "  sudo bash optional/bash-lockdown.sh"
    echo "  sudo bash optional/wireguard-killswitch.sh"
    echo ""

    if [[ "${_FAILED}" -eq 1 ]]; then
        warn "One or more sections had errors. Review output above."
        warn "Log: ${LOG_FILE}"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    mkdir --parents /var/log "${MARKER_DIR}"
    log "=== secure_oss harden.sh v${SCRIPT_VERSION} ==="

    require_root
    require_fedora

    run_section "kernel"     harden_kernel_args
    run_section "sysctl"     harden_sysctl
    run_section "modules"    harden_modules
    run_section "selinux"    harden_selinux
    run_section "firewall"   harden_firewall
    run_section "ssh"        harden_ssh
    run_section "dns"        configure_dns
    run_section "dhcp"       suppress_dhcp_hostname
    run_section "mac"        configure_mac_randomization
    run_section "usbguard"   setup_usbguard
    run_section "mdm"        block_mdm_domains
    run_section "telemetry"  block_telemetry_domains
    run_section "services"   harden_services
    run_section "de"         harden_de
    run_section "coredumps"  harden_coredumps
    run_section "auth"       harden_auth
    run_section "amt"        harden_amt
    run_section "monitor"    setup_monitoring

    print_summary

    [[ "${_FAILED}" -ne 0 ]] && exit 1
    exit 0
}

main "$@"
