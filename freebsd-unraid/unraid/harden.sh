#!/usr/bin/env bash
# harden.sh — Harden Unraid
#
# Platform  : Unraid 6.10+
# Purpose   : Applies a practical security baseline for an Unraid NAS/server:
#             iptables host firewall, SSH hardening, sysctl network hardening,
#             and optional blocking of Unraid.net cloud connectivity.
#             All changes that must survive a reboot are written to /boot/
#             and called from /boot/config/go.
# Tested on : Unraid 6.12
# Requires  : root
#
# Usage:
#   bash harden.sh [--dry-run] [--skip SECTION]
#                  [--local-subnet CIDR] [--ssh-port PORT]
#                  [--web-http-port PORT] [--web-https-port PORT]
#                  [--wireguard-port PORT] [--allow-nfs] [--block-cloud]
#
# Skip sections (--skip, comma-separated):
#   firewall, ssh, sysctl, cloud
#
# Sections applied:
#   1. firewall  — Deploy iptables rules to /boot/config/scripts/ and boot hook
#   2. ssh       — Harden sshd_config in /boot/config/ssh/ (persists across reboots)
#   3. sysctl    — Network stack hardening (written to /boot/config/go)
#   4. cloud     — Block Unraid.net cloud call-home via /etc/hosts (persists via go)
#
# Verification:
#   Firewall : iptables -L INPUT -n -v
#   SSH      : sshd -T | grep -E 'permitrootlogin|passwordauth'
#   Sysctl   : sysctl net.ipv4.conf.all.accept_redirects
#   Cloud    : grep unraid.net /etc/hosts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Defaults (overridden by args or auto-detected)
# ---------------------------------------------------------------------------

DRY_RUN=0
SKIP_SECTIONS=()
LOCAL_SUBNET=""      # auto-detected if empty
SSH_PORT=""          # auto-detected from running sshd or default 22
WEB_HTTP_PORT=""     # auto-detected from /boot/config/ident.cfg
WEB_HTTPS_PORT=""    # auto-detected from /boot/config/ident.cfg
WIREGUARD_PORT=""    # empty = WireGuard not configured
ALLOW_NFS=0          # NFS blocked by default (enable with --allow-nfs)
ALLOW_SMB=1          # SMB allowed from local subnet by default
BLOCK_CLOUD=0        # block unraid.net/myservers call-home (opt-in)

LOG_FILE="/var/log/secure_oss_unraid.log"
MARKER_DIR="/boot/config/secure_oss/applied"
GO_FILE="/boot/config/go"
BOOT_SCRIPTS_DIR="/boot/config/scripts"
BOOT_SSH_DIR="/boot/config/ssh"

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: bash harden.sh [OPTIONS]

Harden Unraid. All persistent changes are written to /boot/config/ and
survive OS reloads from the USB drive.

Options:
  --local-subnet CIDR    Local subnet for firewall rules (default: auto-detect)
                         e.g. 192.168.1.0/24
  --ssh-port PORT        SSH port (default: current sshd port or 22)
  --web-http-port PORT   Unraid web UI HTTP port (default: read from ident.cfg)
  --web-https-port PORT  Unraid web UI HTTPS port (default: read from ident.cfg)
  --wireguard-port PORT  WireGuard UDP port to allow inbound (default: none)
  --allow-nfs            Open NFS ports (2049, 111) from local subnet
  --no-smb               Block SMB ports (default: SMB is allowed from local subnet)
  --block-cloud          Block Unraid.net / myservers call-home endpoints
  --skip SECTIONS        Comma-separated sections to skip:
                         firewall, ssh, sysctl, cloud
  --dry-run              Show what would be done without making changes
  --help                 Show this help
EOF
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log()  { local m="[$(date '+%Y-%m-%d %H:%M:%S')] $*"; echo -e "\033[0;32m${m}\033[0m"; echo "${m}" >> "${LOG_FILE}" 2>/dev/null || true; }
warn() { local m="[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $*"; echo -e "\033[1;33m${m}\033[0m" >&2; echo "${m}" >> "${LOG_FILE}" 2>/dev/null || true; }
die()  { local m="[$(date '+%Y-%m-%d %H:%M:%S')] FATAL: $*"; echo -e "\033[0;31m${m}\033[0m" >&2; exit 1; }

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

write_file() {
    local path="$1" content="$2"
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would write: ${path}\033[0m"
        echo "${content}"
    else
        log "Writing: ${path}"
        mkdir --parents "$(dirname "${path}")"
        echo "${content}" > "${path}"
    fi
}

# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

is_applied() { [[ -f "${MARKER_DIR}/$1" ]]; }
mark_applied() {
    [[ "${DRY_RUN}" == "1" ]] && return
    mkdir --parents "${MARKER_DIR}"
    echo "$(date '+%Y-%m-%d %H:%M:%S')" > "${MARKER_DIR}/$1"
}

should_skip() {
    local section="$1"
    for s in "${SKIP_SECTIONS[@]+"${SKIP_SECTIONS[@]}"}"; do
        [[ "${s}" == "${section}" ]] && return 0
    done
    return 1
}

run_section() {
    local name="$1" fn="$2"
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

_FAILED=0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local-subnet)    LOCAL_SUBNET="${2:?}";    shift 2 ;;
            --ssh-port)        SSH_PORT="${2:?}";         shift 2 ;;
            --web-http-port)   WEB_HTTP_PORT="${2:?}";   shift 2 ;;
            --web-https-port)  WEB_HTTPS_PORT="${2:?}";  shift 2 ;;
            --wireguard-port)  WIREGUARD_PORT="${2:?}";  shift 2 ;;
            --allow-nfs)       ALLOW_NFS=1;               shift   ;;
            --no-smb)          ALLOW_SMB=0;               shift   ;;
            --block-cloud)     BLOCK_CLOUD=1;             shift   ;;
            --skip)            IFS=',' read -ra SKIP_SECTIONS <<< "${2:?}"; shift 2 ;;
            --dry-run)         DRY_RUN=1; warn "Dry-run mode — no changes will be made."; shift ;;
            --help|-h)         usage; exit 0 ;;
            *)                 die "Unknown argument: $1. Run with --help." ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Auto-detection helpers
# ---------------------------------------------------------------------------

detect_local_subnet() {
    # Use the default route's interface to find the local subnet
    local iface subnet
    iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    if [[ -n "${iface}" ]]; then
        subnet="$(ip -o -f inet addr show dev "${iface}" 2>/dev/null \
            | awk '{print $4; exit}')"
        # Convert host address to network address (e.g. 192.168.1.5/24 -> 192.168.1.0/24)
        if command -v python3 &>/dev/null; then
            subnet="$(python3 -c "
import ipaddress, sys
try:
    net = ipaddress.ip_interface('${subnet}').network
    print(str(net))
except Exception:
    print('')
" 2>/dev/null)"
        fi
    fi
    echo "${subnet:-192.168.1.0/24}"
}

detect_web_ports() {
    local ident_cfg="/boot/config/ident.cfg"
    if [[ -f "${ident_cfg}" ]]; then
        WEB_HTTP_PORT="${WEB_HTTP_PORT:-$(grep -E '^PORT=' "${ident_cfg}" \
            | cut -d'=' -f2 | tr -d '"' || echo '80')}"
        WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-$(grep -E '^PORTSSL=' "${ident_cfg}" \
            | cut -d'=' -f2 | tr -d '"' || echo '443')}"
    fi
    WEB_HTTP_PORT="${WEB_HTTP_PORT:-80}"
    WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-443}"
}

detect_ssh_port() {
    SSH_PORT="${SSH_PORT:-$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')}"
    SSH_PORT="${SSH_PORT:-22}"
}

detect_wireguard_port() {
    # If a WireGuard tunnel is configured and active, detect its listen port
    if [[ -z "${WIREGUARD_PORT}" ]] && command -v wg &>/dev/null; then
        WIREGUARD_PORT="$(wg show all listen-port 2>/dev/null | awk '{print $NF; exit}' || true)"
    fi
}

# ---------------------------------------------------------------------------
# Patch /boot/config/go
#
# go runs on every boot. We append a one-liner to call our script if it
# isn't already there. Uses a unique marker comment to stay idempotent.
# ---------------------------------------------------------------------------

patch_go_file() {
    local marker="$1"
    local line="$2"

    if grep --quiet --fixed-strings "${marker}" "${GO_FILE}" 2>/dev/null; then
        log "  ${GO_FILE} already contains: ${marker} — skipping patch"
        return 0
    fi

    log "  Patching ${GO_FILE}: adding ${marker}"
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would append to ${GO_FILE}:\n  ${line}\033[0m"
        return 0
    fi

    printf '\n# %s\n%s\n' "${marker}" "${line}" >> "${GO_FILE}"
}

# ---------------------------------------------------------------------------
# Section 1: Firewall
#
# Generates iptables.sh from the template in scripts/, substituting the
# detected/configured values, copies it to /boot/config/scripts/, and
# patches /boot/config/go to call it on every boot.
# ---------------------------------------------------------------------------

deploy_firewall() {
    local template="${SCRIPT_DIR}/scripts/iptables.sh"
    local dest="${BOOT_SCRIPTS_DIR}/iptables.sh"

    if [[ ! -f "${template}" ]]; then
        die "iptables.sh template not found at ${template}"
    fi

    log "Configuring firewall..."
    log "  Local subnet : ${LOCAL_SUBNET}"
    log "  Web UI       : HTTP=${WEB_HTTP_PORT} HTTPS=${WEB_HTTPS_PORT}"
    log "  SSH          : ${SSH_PORT}"
    log "  SMB          : $([ "${ALLOW_SMB}" = "1" ] && echo "allowed from ${LOCAL_SUBNET}" || echo "blocked")"
    log "  NFS          : $([ "${ALLOW_NFS}" = "1" ] && echo "allowed from ${LOCAL_SUBNET}" || echo "blocked")"
    log "  WireGuard    : ${WIREGUARD_PORT:-not configured}"

    # Substitute placeholders in the template
    local script_content
    script_content="$(sed \
        -e "s|@@LOCAL_SUBNET@@|${LOCAL_SUBNET}|g" \
        -e "s|@@WEB_HTTP_PORT@@|${WEB_HTTP_PORT}|g" \
        -e "s|@@WEB_HTTPS_PORT@@|${WEB_HTTPS_PORT}|g" \
        -e "s|@@SSH_PORT@@|${SSH_PORT}|g" \
        -e "s|@@ALLOW_SMB@@|${ALLOW_SMB}|g" \
        -e "s|@@ALLOW_NFS@@|${ALLOW_NFS}|g" \
        -e "s|@@WIREGUARD_PORT@@|${WIREGUARD_PORT}|g" \
        "${template}")"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would write configured iptables.sh to ${dest}\033[0m"
        echo "${script_content}"
    else
        mkdir --parents "${BOOT_SCRIPTS_DIR}"
        echo "${script_content}" > "${dest}"
        chmod 700 "${dest}"
        log "Wrote firewall script to ${dest}"
    fi

    # Hook into /boot/config/go so it runs on every boot
    patch_go_file \
        "secure_oss: host firewall" \
        "bash ${dest}"

    # Apply immediately (no reboot needed for iptables)
    if [[ "${DRY_RUN}" != "1" ]]; then
        log "Applying firewall rules now..."
        bash "${dest}"
    fi

    mark_applied "firewall"
}

# ---------------------------------------------------------------------------
# Section 2: SSH hardening
#
# Unraid 6.10+ copies /boot/config/ssh/ to /etc/ssh/ on boot, so writing
# a hardened config there makes it persist across OS reloads.
#
# For older Unraid: we also write the live config directly to /etc/ssh/ and
# add a go hook to overwrite it on each subsequent boot.
#
# Key settings (same as ubuntu-server harden.sh):
#   PermitRootLogin no           — root must not log in directly via SSH
#   PasswordAuthentication no    — key-only (only if authorized_keys detected)
#   MaxAuthTries 3               — limit brute force per connection
#   X11Forwarding no             — not needed on a NAS
#   AllowTcpForwarding no        — no tunneling
# ---------------------------------------------------------------------------

harden_ssh() {
    local boot_sshd="${BOOT_SSH_DIR}/sshd_config"
    local live_sshd="/etc/ssh/sshd_config"

    if is_applied "ssh"; then
        log "SSH already hardened — skipping"
        return 0
    fi

    # Safety check before disabling password auth
    local disable_password="no"
    local keys_found=0
    while IFS= read -r -d '' f; do
        [[ -s "${f}" ]] && keys_found=1 && break
    done < <(find /root /home -maxdepth 3 -name "authorized_keys" -print0 2>/dev/null)

    if [[ "${keys_found}" -eq 1 ]]; then
        disable_password="yes"
    else
        warn "No authorized_keys files found — PasswordAuthentication will remain enabled."
        warn "Add your SSH public key to /root/.ssh/authorized_keys, then re-run."
    fi

    local sshd_conf="# secure_oss: hardened sshd_config for Unraid
# Written by harden.sh — persists via /boot/config/ssh/

# --- Authentication ---
PermitRootLogin no
PasswordAuthentication ${disable_password}
PermitEmptyPasswords no
PubkeyAuthentication yes

# --- Brute force mitigation ---
MaxAuthTries 3
LoginGraceTime 30

# --- Session keepalive ---
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Attack surface reduction ---
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintLastLog yes

# --- Crypto: restrict to strong algorithms ---
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"

    # Write to /boot/config/ssh/ (Unraid 6.10+ boot persistence mechanism)
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would write: ${boot_sshd}\033[0m"
        echo "${sshd_conf}"
    else
        mkdir --parents "${BOOT_SSH_DIR}"
        echo "${sshd_conf}" > "${boot_sshd}"
        log "Written to ${boot_sshd} (persists across reboots)"

        # Apply to live system immediately
        cp "${boot_sshd}" "${live_sshd}"

        # Validate and reload
        if sshd -t 2>&1; then
            kill -HUP "$(cat /var/run/sshd.pid 2>/dev/null || echo 0)" 2>/dev/null || \
                systemctl reload sshd 2>/dev/null || \
                warn "Could not reload sshd — new config takes effect after reboot"
        else
            warn "sshd config validation failed — restoring original"
            cp "${live_sshd}.bak" "${live_sshd}" 2>/dev/null || true
            return 1
        fi
    fi

    # Also hook go for older Unraid versions that don't use /boot/config/ssh/
    patch_go_file \
        "secure_oss: ssh hardening" \
        "cp ${boot_sshd} ${live_sshd} && kill -HUP \$(cat /var/run/sshd.pid 2>/dev/null) 2>/dev/null || true"

    log "SSH hardened. PasswordAuthentication=${disable_password}"
    mark_applied "ssh"
}

# ---------------------------------------------------------------------------
# Section 3: Sysctl — network stack hardening
#
# Written to a temp file and applied via sysctl -p immediately.
# Persisted via a go hook that re-applies on every boot (since /etc/sysctl.conf
# resets with the OS).
# ---------------------------------------------------------------------------

configure_sysctl() {
    local boot_sysctl="/boot/config/secure_oss/sysctl-hardening.conf"

    if is_applied "sysctl"; then
        log "Sysctl already configured — skipping"
        return 0
    fi

    write_file "${boot_sysctl}" "# secure_oss: sysctl hardening for Unraid
# Applied on every boot via /boot/config/go

# Disable ICMP redirect acceptance (MITM prevention)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable sending ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets (impossible source addresses)
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP broadcast pings (Smurf attack)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Hide kernel pointers from non-root
kernel.kptr_restrict = 1

# Harden BPF JIT
net.core.bpf_jit_harden = 2

# ===========================================================================
# Internal threat / local privilege escalation hardening
# These params matter when untrusted or potentially malicious content is
# present on the system — including files stored for forensic analysis.
# ===========================================================================

# Disable unprivileged user namespaces.
# User namespaces allow unprivileged processes to create isolated namespaces
# that appear to have root inside them. This is the most commonly exploited
# kernel feature in container escapes and local privilege escalation CVEs.
# Docker and rootful containers are NOT affected — only rootless/unprivileged
# namespace creation by non-root processes is blocked.
kernel.unprivileged_userns_clone = 0

# Restrict ptrace to parent/child relationships only.
# ptrace allows one process to inspect and control another. Unrestricted ptrace
# lets any process running as the same user inspect other processes, read their
# memory, and inject code. Value 1 = only a process's parent may ptrace it.
kernel.yama.ptrace_scope = 1

# Restrict access to perf events.
# The perf subsystem can expose kernel addresses and timing data useful for
# side-channel attacks (Spectre variants, cache timing). Value 3 = root only.
kernel.perf_event_paranoid = 3

# Set minimum mmap address (null pointer dereference mitigation).
# Prevents userspace from mapping memory at address 0x0, which would turn a
# kernel null pointer dereference bug into an exploitable privilege escalation.
vm.mmap_min_addr = 65536

# Protect hardlinks from privilege escalation.
# Without this, a non-root user can hardlink a setuid binary they don't own.
# If the owner later fixes a bug in it, the attacker's hardlink still points
# to the old vulnerable version.
fs.protected_hardlinks = 1

# Protect symlinks from TOCTOU attacks.
# Prevents following symlinks in world-writable sticky directories (e.g. /tmp)
# when the symlink owner differs from the follower. Blocks classic temp-file
# symlink attacks used to escalate privileges or overwrite arbitrary files.
fs.protected_symlinks = 1

# Prevent setuid/setgid programs from creating core dumps.
# Core dumps of privileged processes can leak sensitive memory (credentials,
# keys) and can be placed in attacker-controlled locations for exploitation.
fs.suid_dumpable = 0"

    # Apply immediately
    if [[ "${DRY_RUN}" != "1" ]]; then
        sysctl -p "${boot_sysctl}" 2>/dev/null || \
            warn "Some sysctl values may not apply on this kernel — they will be retried on reboot"
    fi

    # Persist via /boot/config/go
    patch_go_file \
        "secure_oss: sysctl hardening" \
        "sysctl -p ${boot_sysctl} 2>/dev/null || true"

    mark_applied "sysctl"
}

# ---------------------------------------------------------------------------
# Section 4: Block Unraid.net cloud call-home (opt-in)
#
# Unraid's "Connect" / "myservers" plugin phones home to unraid.net for
# remote management, license validation, and usage telemetry. If you do not
# use Unraid Connect and want to prevent all outbound connections to Unraid's
# cloud infrastructure, this section null-routes the relevant domains.
#
# /etc/hosts resets on boot, so we persist the entries via /boot/config/go.
#
# NOTE: This does NOT affect local Unraid functionality, shares, Docker, or
# VMs. It only prevents the Unraid OS itself from reaching unraid.net.
# The Unraid Connect dashboard (connect.myunraid.net) will stop working.
# ---------------------------------------------------------------------------

block_cloud() {
    local hosts_snippet="/boot/config/secure_oss/hosts-unraid-cloud.txt"

    if is_applied "cloud"; then
        log "Cloud blocking already configured — skipping"
        return 0
    fi

    write_file "${hosts_snippet}" "# secure_oss: null-route Unraid.net cloud endpoints
# Applied via /boot/config/go on every boot
0.0.0.0  unraid.net
0.0.0.0  www.unraid.net
0.0.0.0  connect.unraid.net
0.0.0.0  myunraid.net
0.0.0.0  connect.myunraid.net
0.0.0.0  account.unraid.net
0.0.0.0  keys.unraid.net
0.0.0.0  api.unraid.net
0.0.0.0  flash.unraid.net
0.0.0.0  dynamix.com
0.0.0.0  dnld.unraid.net"

    # Patch go to append entries to /etc/hosts on every boot
    patch_go_file \
        "secure_oss: block unraid.net cloud" \
        "cat ${hosts_snippet} >> /etc/hosts"

    # Apply immediately to the live system
    if [[ "${DRY_RUN}" != "1" ]]; then
        cat "${hosts_snippet}" >> /etc/hosts
        log "Unraid.net cloud endpoints null-routed in /etc/hosts"
    fi

    warn "Unraid Connect dashboard will no longer be reachable."
    warn "To undo: remove ${hosts_snippet} and remove the go hook, then reboot."

    mark_applied "cloud"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo -e "\033[1m=== Hardening Summary ===\033[0m"
    echo ""

    local sections=(firewall ssh sysctl cloud)
    for section in "${sections[@]}"; do
        if is_applied "${section}"; then
            echo -e "  \033[0;32m✓\033[0m ${section}"
        elif should_skip "${section}"; then
            echo -e "  \033[1;33m−\033[0m ${section} (skipped)"
        else
            echo -e "  \033[0;31m✗\033[0m ${section} (not applied or failed)"
        fi
    done

    echo ""
    echo "Verification commands:"
    echo "  Firewall : iptables -L INPUT -n -v"
    echo "             iptables -L DOCKER-USER -n -v"
    echo "  SSH      : sshd -T | grep -E 'permitrootlogin|passwordauth|maxauthtries'"
    echo "  Sysctl   : sysctl net.ipv4.conf.all.accept_redirects net.ipv4.tcp_syncookies"
    [[ "${BLOCK_CLOUD}" == "1" ]] && \
    echo "  Cloud    : grep unraid.net /etc/hosts"
    echo ""
    echo "Persistent config written to:"
    echo "  Firewall : ${BOOT_SCRIPTS_DIR}/iptables.sh  (called from ${GO_FILE})"
    echo "  SSH      : ${BOOT_SSH_DIR}/sshd_config"
    echo "  Sysctl   : /boot/config/secure_oss/sysctl-hardening.conf"
    echo ""

    if [[ "${_FAILED}" -eq 1 ]]; then
        warn "One or more sections encountered errors. Review output above."
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
    log "=== secure_oss Unraid harden.sh ==="

    if [[ "${EUID}" -ne 0 ]]; then
        die "Must be run as root."
    fi

    if ! grep --quiet --ignore-case "unraid" /etc/os-release 2>/dev/null \
        && ! [[ -f /boot/config/go ]]; then
        die "This script must be run on Unraid (/boot/config/go not found)."
    fi

    # Auto-detect values not provided via args
    [[ -z "${LOCAL_SUBNET}" ]]  && LOCAL_SUBNET="$(detect_local_subnet)"
    detect_web_ports
    detect_ssh_port
    detect_wireguard_port

    log "Detected configuration:"
    log "  Local subnet  : ${LOCAL_SUBNET}"
    log "  Web UI        : HTTP=${WEB_HTTP_PORT} HTTPS=${WEB_HTTPS_PORT}"
    log "  SSH port      : ${SSH_PORT}"
    log "  WireGuard     : ${WIREGUARD_PORT:-not detected}"

    run_section "firewall" deploy_firewall
    run_section "ssh"      harden_ssh
    run_section "sysctl"   configure_sysctl

    if [[ "${BLOCK_CLOUD}" == "1" ]]; then
        run_section "cloud" block_cloud
    else
        log "Cloud blocking skipped (pass --block-cloud to enable)"
    fi

    print_summary

    [[ "${_FAILED}" -ne 0 ]] && exit 1
    return 0
}

main "$@"
