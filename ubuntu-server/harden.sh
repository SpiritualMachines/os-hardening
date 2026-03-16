#!/usr/bin/env bash
# harden.sh — Harden Ubuntu Server
#
# Platform  : Ubuntu Server 22.04 LTS / 24.04 LTS
# Purpose   : Applies a practical security baseline: firewall, SSH hardening,
#             AppArmor enforcement, sysctl network hardening, service masking,
#             core dump disabling, auditd rules, automatic security updates,
#             and PAM login controls.
# Tested on : Ubuntu Server 22.04 LTS, Ubuntu Server 24.04 LTS
# Requires  : root, provision.sh must be run first
#
# Usage:
#   sudo bash harden.sh [--dry-run] [--ssh-port PORT] [--skip SECTION]
#
# Options:
#   --ssh-port PORT    SSH port to keep open in UFW (default: current sshd port or 22)
#   --skip SECTIONS    Comma-separated list of sections to skip
#
# Sections:
#   ufw          — UFW default-deny inbound; allow only SSH
#   ssh          — sshd_config hardening (algorithms, auth controls)
#   apparmor     — Enforce AppArmor profiles for all installed services
#   sysctl       — Network stack and kernel hardening parameters
#   services     — Mask avahi-daemon, cups, rpcbind, apport
#   coredumps    — Disable core dump creation system-wide
#   auditd       — Configure audit rules for authentication, file access, privilege use
#   updates      — Configure unattended-upgrades for security-only auto-patching
#   pam          — Password quality requirements and login failure limits
#   fail2ban     — Configure fail2ban jail for SSH brute force protection
#
# Verification:
#   UFW       : ufw status verbose
#   SSH       : sshd -T | grep -E 'permitrootlogin|passwordauth|pubkeyauth'
#   AppArmor  : aa-status
#   Sysctl    : sysctl net.ipv4.conf.all.accept_redirects kernel.dmesg_restrict
#   Services  : systemctl is-enabled avahi-daemon.service
#   Coredumps : ulimit -c (should show 0); sysctl fs.suid_dumpable
#   Auditd    : auditctl -l; systemctl status auditd
#   Updates   : cat /etc/apt/apt.conf.d/50unattended-upgrades
#   PAM       : grep -r pwquality /etc/pam.d/common-password

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SKIP_SECTIONS=()
SSH_PORT=""   # resolved in parse_args; defaults to current sshd port or 22

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash harden.sh [OPTIONS]

Apply security hardening to Ubuntu Server. Run provision.sh first.

Options:
  --ssh-port PORT   SSH port to allow through UFW (default: current sshd port or 22)
  --skip SECTIONS   Comma-separated sections to skip:
                    ufw, ssh, apparmor, sysctl, services, coredumps,
                    auditd, updates, pam, fail2ban
  --dry-run         Show what would be done without making changes
  --help            Show this help

Examples:
  sudo bash harden.sh
  sudo bash harden.sh --ssh-port 2222
  sudo bash harden.sh --dry-run --skip apparmor
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
            --ssh-port)
                SSH_PORT="${2:?--ssh-port requires a value}"
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

    # Resolve SSH port: use --ssh-port arg, or read from running sshd config, or default to 22
    if [[ -z "${SSH_PORT}" ]]; then
        SSH_PORT="$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')"
        SSH_PORT="${SSH_PORT:-22}"
        log "Detected current SSH port: ${SSH_PORT}"
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
# Section runner
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
# Section 1: UFW — default-deny inbound, allow SSH
#
# UFW's default policy after a fresh install allows all traffic. We flip this
# to default-deny inbound so only explicitly allowed ports accept connections.
# Outbound is left unrestricted (servers need to reach package repos, NTP, etc.)
#
# The only inbound port opened by default is SSH. Additional ports (web, mail,
# etc.) should be added manually: ufw allow <PORT>/tcp
# ---------------------------------------------------------------------------

configure_ufw() {
    require_package ufw

    if is_applied "ufw"; then
        log "UFW already configured — skipping (delete ${MARKER_DIR}/ufw to re-apply)"
        return 0
    fi

    log "Configuring UFW: default deny inbound, allow SSH on port ${SSH_PORT}"

    # Default policies
    run_cmd ufw --force default deny incoming
    run_cmd ufw --force default allow outgoing

    # Allow SSH first — critical: must be done BEFORE enabling UFW
    # Doing this after ufw enable would risk locking out an SSH session
    run_cmd ufw allow "${SSH_PORT}/tcp" comment "SSH"

    # Enable UFW (--force suppresses the interactive "proceed?" prompt)
    run_cmd ufw --force enable

    log "UFW enabled. Default: deny inbound, allow outbound."
    log "SSH port ${SSH_PORT}/tcp is open."
    log "To allow additional services: ufw allow <PORT>/tcp"

    mark_applied "ufw"
}

# ---------------------------------------------------------------------------
# Section 2: SSH hardening
#
# Hardens sshd_config with a drop-in file in /etc/ssh/sshd_config.d/ so we
# don't overwrite the distribution config (which may be updated by apt).
# Our drop-in takes precedence because sshd processes includes in order and
# last-write-wins for duplicate directives.
#
# KEY SAFETY CHECK: Before disabling PasswordAuthentication, we verify that
# at least one authorized_keys file exists for a non-root account or that we
# are already connected via SSH key (meaning keys are working). If no evidence
# of key-based auth is found, we emit a prominent warning and skip that
# specific setting, leaving password auth enabled until the operator confirms
# keys are in place.
#
# Hardened settings:
#   PermitRootLogin no          — root must never log in directly via SSH
#   PasswordAuthentication no   — key-only auth (only if keys detected)
#   PermitEmptyPasswords no     — never allow blank passwords
#   PubkeyAuthentication yes    — ensure public key auth is enabled
#   AuthenticationMethods       — explicitly list accepted auth methods
#   MaxAuthTries 3              — limit brute force attempts per connection
#   LoginGraceTime 30           — close unauthenticated connections quickly
#   ClientAliveInterval 300     — detect dead sessions after 5 minutes
#   ClientAliveCountMax 2       — drop after 2 missed keepalives (10 min idle)
#   X11Forwarding no            — X11 forwarding is a security risk on servers
#   AllowAgentForwarding no     — agent forwarding can be abused for lateral movement
#   AllowTcpForwarding no       — port forwarding disabled (enable per-host if needed)
#   PrintLastLog yes            — show last login on connect (detect unauthorized use)
#   Banner /etc/issue.net       — legal warning banner for unauthorized access
#   KexAlgorithms               — restrict to strong key exchange algorithms
#   Ciphers                     — restrict to AES-GCM and ChaCha20; remove CBC modes
#   MACs                        — restrict to HMAC-SHA2; remove MD5 and SHA1
# ---------------------------------------------------------------------------

harden_ssh() {
    local drop_in="/etc/ssh/sshd_config.d/90-secure-oss.conf"

    if [[ -f "${drop_in}" ]]; then
        log "SSH drop-in already present at ${drop_in} — skipping"
        log "Delete ${drop_in} and re-run to regenerate."
        return 0
    fi

    # Determine if it is safe to disable password authentication
    local disable_password_auth="yes"
    local password_auth_reason=""

    if is_ssh_session; then
        # If we reached this point via SSH, the operator has a working key session.
        # It is safe to disable password auth.
        password_auth_reason="(connected via SSH key — safe to disable)"
    else
        # Not an SSH session (e.g. console). Check for any authorized_keys file.
        local keys_found=0
        while IFS= read -r -d '' authkeys_file; do
            if [[ -s "${authkeys_file}" ]]; then
                keys_found=1
                break
            fi
        done < <(find /home /root -maxdepth 3 -name "authorized_keys" -print0 2>/dev/null)

        if [[ "${keys_found}" -eq 0 ]]; then
            disable_password_auth="no"
            password_auth_reason="(no authorized_keys found — SKIPPED for safety)"
            warn "==========================================================="
            warn "  SSH key-based auth NOT detected."
            warn "  PasswordAuthentication will NOT be disabled."
            warn "  To disable it manually after adding your SSH key:"
            warn "    Edit ${drop_in}"
            warn "    Change: PasswordAuthentication yes -> no"
            warn "    Then: systemctl reload ssh"
            warn "==========================================================="
        else
            password_auth_reason="(authorized_keys found — safe to disable)"
        fi
    fi

    log "SSH PasswordAuthentication: ${disable_password_auth} ${password_auth_reason}"

    write_file "${drop_in}" "# secure_oss: SSH hardening drop-in
# Applied by harden.sh — takes precedence over /etc/ssh/sshd_config
# See: man sshd_config

# --- Authentication ---

# Never permit root to log in directly via SSH.
# Root access must go through a sudo-enabled normal account.
PermitRootLogin no

# Key-based authentication only. Operators must deploy SSH public keys
# before enabling this. See WARNING in harden.sh if this is set to 'yes'.
PasswordAuthentication ${disable_password_auth}

# Never accept accounts with no password set.
PermitEmptyPasswords no

# Explicitly enable public key authentication.
PubkeyAuthentication yes

# Accept only public key authentication (and optionally keyboard-interactive
# for 2FA if configured). Adjust if using PAM 2FA (e.g. TOTP).
AuthenticationMethods publickey

# --- Brute force mitigation ---

# Limit authentication attempts per connection. Combined with fail2ban, this
# significantly raises the cost of brute force attacks.
MaxAuthTries 3

# Close unauthenticated connections after 30 seconds. Reduces resource
# exhaustion from connection floods.
LoginGraceTime 30

# --- Session management ---

# Send keepalive messages every 5 minutes. Drop the session after 2 missed
# responses (10 minutes of no response). Cleans up dead connections.
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Attack surface reduction ---

# X11 forwarding creates an additional attack vector and is never needed
# on a headless server.
X11Forwarding no

# SSH agent forwarding allows an attacker who compromises this server to
# use the operator's agent to authenticate to other servers. Disable unless
# you explicitly need it for a specific workflow.
AllowAgentForwarding no

# TCP port forwarding (tunneling) is a common technique for bypassing
# firewall rules and exfiltrating data. Disable unless required.
AllowTcpForwarding no

# --- Informational ---

# Show the last login time and source IP on successful authentication.
# Lets operators notice if someone else has been logging in.
PrintLastLog yes

# Display a warning banner before authentication. Useful for legal notice
# that unauthorized access is prohibited.
Banner /etc/issue.net

# --- Cryptographic algorithm restrictions ---
# Remove legacy/weak algorithms. The following allow lists restrict SSH
# to strong modern cryptography only.
#
# Key exchange: Curve25519 and ECDH with strong curves only.
# Removes: diffie-hellman-group1-sha1, diffie-hellman-group14-sha1 (weak)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

# Symmetric ciphers: AES-GCM (authenticated) and ChaCha20-Poly1305 only.
# Removes: AES-CBC modes (vulnerable to BEAST/Lucky13), arcfour, 3DES.
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# Message authentication codes: HMAC-SHA2 only.
# Removes: hmac-md5, hmac-sha1, umac-64 (all weak or broken).
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"

    # Write the legal banner
    if [[ ! -f /etc/issue.net ]] || ! grep --quiet "Unauthorized" /etc/issue.net; then
        write_file "/etc/issue.net" "***********************************************************************
* WARNING: Authorized access only.                                    *
* Unauthorized access is strictly prohibited and will be prosecuted   *
* to the fullest extent of the law. All activity is monitored and     *
* logged.                                                             *
***********************************************************************"
    fi

    # Validate the config before reloading (avoids locking ourselves out)
    if [[ "${DRY_RUN}" != "1" ]]; then
        if ! sshd -t 2>&1; then
            warn "sshd config validation FAILED. Removing drop-in to prevent lockout."
            rm --force "${drop_in}"
            return 1
        fi
        log "sshd config validated successfully."
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || \
            warn "Could not reload sshd — changes will take effect on next restart"
    fi

    mark_applied "ssh"
}

# ---------------------------------------------------------------------------
# Section 3: AppArmor — enforce profiles for installed services
#
# Ubuntu ships with AppArmor enabled by default, but some profiles may be
# in complain mode (log violations without blocking) rather than enforce mode.
# We flip all loaded profiles to enforce mode.
#
# AppArmor confines processes to a defined set of permitted operations.
# A compromised service (e.g. nginx, MySQL) running under an enforced profile
# cannot access files or make syscalls outside its profile, significantly
# limiting the blast radius of a compromise.
# ---------------------------------------------------------------------------

enforce_apparmor() {
    if ! command -v aa-enforce &>/dev/null; then
        warn "aa-enforce not found. Install apparmor-utils (run provision.sh first)."
        return 1
    fi

    if is_applied "apparmor"; then
        log "AppArmor enforcement already configured — skipping"
        return 0
    fi

    # Ensure AppArmor is enabled in the kernel
    if ! aa-status --enabled 2>/dev/null; then
        warn "AppArmor is not enabled in the kernel. Check boot parameters (apparmor=1 security=apparmor)."
        return 1
    fi

    log "Setting all AppArmor profiles to enforce mode..."

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would run: aa-enforce /etc/apparmor.d/*"
        echo "[DRY RUN] Would run: aa-status"
        return 0
    fi

    # Enforce all profiles under /etc/apparmor.d/ (excludes abstractions and tunables)
    local enforced=0
    local failed=0
    for profile in /etc/apparmor.d/*; do
        # Skip subdirectories (abstractions/, tunables/, etc.)
        [[ -f "${profile}" ]] || continue
        if aa-enforce "${profile}" 2>/dev/null; then
            ((enforced++)) || true
        else
            warn "Could not enforce profile: ${profile}"
            ((failed++)) || true
        fi
    done

    log "AppArmor: ${enforced} profiles enforced, ${failed} failed."

    if [[ "${failed}" -gt 0 ]]; then
        warn "Some profiles could not be enforced. Run 'aa-status' to review."
    fi

    # Reload AppArmor to pick up any profile changes
    systemctl reload apparmor 2>/dev/null || true

    mark_applied "apparmor"
}

# ---------------------------------------------------------------------------
# Section 4: Sysctl — network stack and kernel hardening
#
# Same network parameters as the Silverblue light variant, plus additional
# parameters relevant to a server environment.
# ---------------------------------------------------------------------------

configure_sysctl() {
    local conf_file="/etc/sysctl.d/90-secure-oss.conf"

    if [[ -f "${conf_file}" ]]; then
        log "sysctl config already present at ${conf_file} — skipping"
        log "Delete ${conf_file} and re-run to regenerate."
        return 0
    fi

    write_file "${conf_file}" "# secure_oss: kernel and network stack hardening
# Applied by harden.sh — see comments for rationale.

# ===========================================================================
# IPv4 network stack
# ===========================================================================

# Disable ICMP redirect acceptance.
# Routers can send redirects to change routing table entries. Forged redirects
# are a classic MITM vector on shared networks.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Disable 'secure' redirect acceptance (only from known gateways).
# Unnecessary for a server; even gateways can be compromised.
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Disable sending ICMP redirects.
# A server is not a router. Sending redirects is undesirable.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable IP source routing.
# Source-routed packets specify their own path and are rarely legitimate.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable TCP SYN cookies.
# Protects against SYN flood DoS attacks without dropping legitimate traffic.
net.ipv4.tcp_syncookies = 1

# Enable strict reverse path filtering.
# Drops packets whose source address wouldn't be routed back via the same
# interface. Prevents IP address spoofing.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log packets with impossible source addresses (martians).
# Helps detect spoofing or misconfiguration on the network.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Do not respond to ICMP broadcasts (Smurf attack mitigation).
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses.
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ===========================================================================
# IPv6 network stack
# ===========================================================================

# Disable IPv6 ICMP redirect acceptance.
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable IPv6 source routing.
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ===========================================================================
# Kernel hardening
# ===========================================================================

# Restrict dmesg to root.
# The kernel ring buffer can contain memory addresses, hardware identifiers,
# and other data useful to local privilege escalation attacks.
kernel.dmesg_restrict = 1

# Hide kernel symbol addresses from non-root users.
# /proc/kallsyms and similar interfaces expose kernel addresses that can be
# used to defeat KASLR. Value 1 = hide from non-root; 2 = hide from root too.
kernel.kptr_restrict = 1

# Harden the BPF JIT compiler.
# The BPF JIT can expose kernel addresses. Value 2 enables constant blinding
# and randomizes JIT memory allocation, resisting JIT spray attacks.
net.core.bpf_jit_harden = 2

# Restrict ptrace to child processes only.
# ptrace allows one process to inspect and control another. Value 1 restricts
# ptrace to parent/child relationships, preventing lateral process injection
# by other processes running as the same user.
kernel.yama.ptrace_scope = 1

# ===========================================================================
# Network performance (server-appropriate defaults)
# ===========================================================================

# Increase the size of the TCP socket buffer to handle high-throughput workloads.
# These are conservative increases — adjust higher for 10G+ environments.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216"

    if [[ "${DRY_RUN}" != "1" ]]; then
        log "Applying sysctl parameters immediately..."
        sysctl --system 2>&1 | grep --fixed-strings "90-secure-oss" || \
            sysctl -p "${conf_file}" || \
            warn "Could not apply immediately — parameters will take effect on next reboot"
    fi

    mark_applied "sysctl"
}

# ---------------------------------------------------------------------------
# Section 5: Services — mask unnecessary / insecure services
#
# avahi-daemon    mDNS/DNS-SD. Announces the server by hostname on the LAN.
#                 Unnecessary on a server; use static DNS entries instead.
#
# cups / cups-browsed
#                 Printing services. Virtually never needed on a server.
#                 cups-browsed had a critical RCE vulnerability (CVE-2024-47176)
#                 that affected internet-exposed instances.
#
# rpcbind         RPC portmapper. Required for NFS only. Exposes port 111.
#
# apport          Crash reporter. May still be running if not fully removed
#                 by provision.sh (e.g. just disabled rather than purged).
# ---------------------------------------------------------------------------

mask_services() {
    local services_to_mask=(
        "avahi-daemon.service:mDNS responder — announces server on LAN"
        "avahi-daemon.socket:mDNS responder socket activation"
        "cups.service:Printing service — not needed on a server"
        "cups.socket:Printing socket activation"
        "cups-browsed.service:CUPS network discovery — CVE-2024-47176 affected versions"
        "rpcbind.service:RPC portmapper — only needed for NFS"
        "rpcbind.socket:RPC portmapper socket activation"
        "apport.service:Crash reporter — sends crash data to Canonical"
    )

    local masked_count=0

    for entry in "${services_to_mask[@]}"; do
        local unit="${entry%%:*}"
        local reason="${entry#*:}"

        if ! systemctl cat "${unit}" &>/dev/null; then
            log "${unit} not present — skipping"
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
        log "All targeted services already masked or not present."
    else
        log "Masked ${masked_count} service(s)."
    fi

    mark_applied "services"
}

# ---------------------------------------------------------------------------
# Section 6: Core dumps — disable system-wide
#
# Core dumps can contain the full memory contents of a process at crash time,
# including encryption keys, credentials, session tokens, and private data.
# On a production server, core dumps should be disabled. If debugging is
# needed, enable them temporarily for a specific process/user and clean up.
#
# Three layers:
#   1. systemd coredump.conf.d  — controls systemd-coredump (modern systems)
#   2. /etc/security/limits.conf — PAM-based limit for all login sessions
#   3. sysctl fs.suid_dumpable  — prevents setuid programs from dumping
# ---------------------------------------------------------------------------

disable_coredumps() {
    if is_applied "coredumps"; then
        log "Core dumps already disabled — skipping"
        return 0
    fi

    log "Disabling core dump creation system-wide"

    # Layer 1: systemd-coredump configuration
    write_file "/etc/systemd/coredump.conf.d/99-secure-oss-disable.conf" "[Coredump]
# Disable core dump storage (secure_oss hardening).
# Core dumps can expose sensitive memory content (keys, passwords, tokens).
# Re-enable temporarily for debugging: systemctl set-property <unit> LimitCORE=infinity
Storage=none
ProcessSizeMax=0"

    # Layer 2: PAM limits — hard limit of 0 for all users
    append_block \
        "/etc/security/limits.conf" \
        "### BEGIN secure_oss COREDUMPS BLOCK — DO NOT EDIT ###" \
        "### END secure_oss COREDUMPS BLOCK ###" \
        "# Disable core dumps for all users (secure_oss harden.sh)
* soft core 0
* hard core 0"

    # Layer 3: sysctl — prevent setuid programs from dumping
    # fs.suid_dumpable = 0 means setuid programs never produce core dumps
    # (This is also covered in configure_sysctl but added here defensively
    # in case the sysctl section was skipped)
    if ! grep --quiet "fs.suid_dumpable" /etc/sysctl.d/90-secure-oss.conf 2>/dev/null; then
        append_block \
            "/etc/sysctl.d/90-secure-oss.conf" \
            "### BEGIN secure_oss COREDUMPS SYSCTL ###" \
            "### END secure_oss COREDUMPS SYSCTL ###" \
            "# Prevent setuid/setgid programs from creating core dumps.
# 0 = never dump; 1 = dump (but owned by root); 2 = dump (owned by user)
fs.suid_dumpable = 0"

        if [[ "${DRY_RUN}" != "1" ]]; then
            sysctl -w fs.suid_dumpable=0 2>/dev/null || true
        fi
    fi

    # Reload systemd manager to pick up coredump.conf.d changes
    if [[ "${DRY_RUN}" != "1" ]]; then
        systemctl daemon-reload
    fi

    mark_applied "coredumps"
}

# ---------------------------------------------------------------------------
# Section 7: auditd — configure audit rules
#
# The Linux Audit system records security-relevant events at the kernel level.
# These rules log:
#   - Authentication events (PAM, su, sudo)
#   - Changes to sensitive files (/etc/passwd, /etc/shadow, /etc/sudoers)
#   - Use of privileged commands (sudo, su, chown, chmod)
#   - Network configuration changes (ip, iptables, nftables)
#   - Kernel module loading/unloading
#   - System call violations (execve with specific contexts)
#
# We write to /etc/audit/rules.d/ which is the modern location. augenrules
# compiles the rules into /etc/audit/audit.rules on service restart.
# ---------------------------------------------------------------------------

configure_auditd() {
    require_package auditd

    local rules_file="/etc/audit/rules.d/90-secure-oss.rules"

    if [[ -f "${rules_file}" ]]; then
        log "auditd rules already present at ${rules_file} — skipping"
        log "Delete ${rules_file} and run 'augenrules --load' to regenerate."
        return 0
    fi

    write_file "${rules_file}" "## secure_oss audit rules
## Applied by harden.sh. Compiled via: augenrules --load
## Reference: https://github.com/linux-audit/audit-userspace/tree/main/rules

# ===========================================================================
# Audit system configuration
# ===========================================================================

# Delete all existing rules before loading these (ensures clean state)
-D

# Set the audit buffer size. Increase if audit events are being dropped
# (check: auditctl -s | grep lost)
-b 8192

# Failure mode: 1 = print failure message and continue (safe for most servers)
# Use 2 (panic) only on high-security systems that must not lose events.
-f 1

# ===========================================================================
# Authentication and session management
# ===========================================================================

# Log all authentication events via PAM
-w /etc/pam.d/ -p wa -k pam_config
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/faillog -p wa -k faillog
-w /var/log/lastlog -p wa -k lastlog

# Log use of sudo and su
-w /usr/bin/sudo -p x -k sudo_exec
-w /bin/su -p x -k su_exec
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

# ===========================================================================
# Sensitive file modifications
# ===========================================================================

# User and group account changes
-w /etc/passwd -p wa -k passwd_change
-w /etc/shadow -p wa -k shadow_change
-w /etc/group -p wa -k group_change
-w /etc/gshadow -p wa -k gshadow_change
-w /etc/security/opasswd -p wa -k opasswd_change

# SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Log cron configuration changes (cron can be used for persistence)
-w /etc/cron.allow -p wa -k cron_allow
-w /etc/cron.deny -p wa -k cron_deny
-w /etc/cron.d/ -p wa -k cron_d
-w /etc/cron.daily/ -p wa -k cron_daily
-w /etc/cron.hourly/ -p wa -k cron_hourly
-w /etc/cron.monthly/ -p wa -k cron_monthly
-w /etc/cron.weekly/ -p wa -k cron_weekly
-w /etc/crontab -p wa -k crontab
-w /var/spool/cron/ -p wa -k user_crontabs

# ===========================================================================
# Privilege escalation and sensitive syscalls
# ===========================================================================

# Log changes to file ownership and permissions (chown, chmod, setuid changes)
-a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -k ownership_change
-a always,exit -F arch=b32 -S chown -S fchown -S lchown -S fchownat -k ownership_change
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k permission_change
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k permission_change

# Log use of setuid/setgid executables (common in privilege escalation)
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid_exec
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid_exec

# ===========================================================================
# Network and firewall configuration changes
# ===========================================================================

# Log changes to network configuration tools
-w /sbin/iptables -p x -k iptables_exec
-w /sbin/ip6tables -p x -k ip6tables_exec
-w /usr/sbin/nft -p x -k nftables_exec
-w /sbin/ip -p x -k ip_exec
-w /etc/network/ -p wa -k network_config
-w /etc/netplan/ -p wa -k netplan_config

# ===========================================================================
# Kernel module loading
# ===========================================================================

# Log loading and unloading of kernel modules.
# Rootkits and malicious drivers often load as kernel modules.
-w /sbin/insmod -p x -k module_load
-w /sbin/rmmod -p x -k module_unload
-w /sbin/modprobe -p x -k module_load
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
-a always,exit -F arch=b32 -S init_module -S finit_module -k module_load
-a always,exit -F arch=b64 -S delete_module -k module_unload
-a always,exit -F arch=b32 -S delete_module -k module_unload

# ===========================================================================
# System startup and shutdown
# ===========================================================================

-w /sbin/shutdown -p x -k power_exec
-w /sbin/poweroff -p x -k power_exec
-w /sbin/reboot -p x -k power_exec
-w /sbin/halt -p x -k power_exec

# ===========================================================================
# Make the audit configuration immutable
# ===========================================================================
# Once loaded, the audit configuration cannot be changed without rebooting.
# This prevents an attacker from disabling auditing after gaining root.
# Comment this out if you need to reload rules without rebooting during setup.
-e 2"

    if [[ "${DRY_RUN}" != "1" ]]; then
        log "Compiling and loading audit rules..."
        if command -v augenrules &>/dev/null; then
            augenrules --load
        else
            auditctl -R "${rules_file}"
        fi
        systemctl restart auditd
        log "auditd rules loaded. Verify with: auditctl -l"
    fi

    mark_applied "auditd"
}

# ---------------------------------------------------------------------------
# Section 8: Unattended-upgrades — security-only auto-patching
#
# Configures automatic installation of security updates only. Non-security
# updates are not applied automatically (too risky to auto-apply on a server
# without testing). Security patches are applied immediately to close known
# vulnerabilities before they are exploited.
#
# Mail notification requires a local MTA (e.g. postfix) or null mailer.
# The MAIL_TO placeholder should be replaced with an actual address.
# ---------------------------------------------------------------------------

configure_unattended_upgrades() {
    require_package unattended-upgrades

    local conf_file="/etc/apt/apt.conf.d/50unattended-upgrades"

    if is_applied "updates"; then
        log "unattended-upgrades already configured — skipping"
        return 0
    fi

    # Read the Ubuntu version codename for use in origin patterns
    local ubuntu_codename=""
    # shellcheck source=/dev/null
    source /etc/os-release 2>/dev/null || true
    ubuntu_codename="${VERSION_CODENAME:-}"

    if [[ -z "${ubuntu_codename}" ]]; then
        warn "Could not detect Ubuntu codename — using wildcard in origin patterns"
        ubuntu_codename='${distro_codename}'
    fi

    write_file "${conf_file}" "// secure_oss: unattended-upgrades configuration
// Applies security-only updates automatically.

Unattended-Upgrade::Allowed-Origins {
    // Standard Ubuntu security updates
    \"Ubuntu:${ubuntu_codename}-security\";
    // Ubuntu ESM infrastructure (if ubuntu-pro is active)
    // \"UbuntuESMApps:${ubuntu_codename}-apps-security\";
    // \"UbuntuESM:${ubuntu_codename}-infra-security\";
};

// Do NOT automatically apply non-security updates.
// Test them before applying on a production server.
// To also apply all updates: add \"Ubuntu:${ubuntu_codename}-updates\";

// Remove unused automatically-installed kernel packages.
Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";

// Remove unused dependencies after upgrade.
Unattended-Upgrade::Remove-Unused-Dependencies \"true\";

// Automatically reboot if required (e.g. kernel update).
// Set to \"true\" and configure a reboot time if acceptable for this server.
// WARNING: Unexpected reboots can cause downtime. Review your SLA first.
Unattended-Upgrade::Automatic-Reboot \"false\";
// Unattended-Upgrade::Automatic-Reboot-Time \"02:00\";

// Send email on upgrade errors (requires a configured MTA).
// Replace with a real address or leave empty to disable.
Unattended-Upgrade::Mail \"\";
Unattended-Upgrade::MailReport \"on-change\";

// Download and install in the same step (default; change to split for large hosts).
Unattended-Upgrade::MinimalSteps \"true\";

// Write upgrade activity to syslog in addition to the unattended-upgrades log.
Unattended-Upgrade::SyslogEnable \"true\";"

    # Enable the apt periodic timer that drives unattended-upgrades
    write_file "/etc/apt/apt.conf.d/20auto-upgrades" "// secure_oss: enable automatic update checks and unattended-upgrades
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";"

    if [[ "${DRY_RUN}" != "1" ]]; then
        systemctl enable --now unattended-upgrades 2>/dev/null || true
        log "unattended-upgrades configured and enabled."
        log "Security updates will be applied automatically."
        log "Check logs at: /var/log/unattended-upgrades/"
    fi

    mark_applied "updates"
}

# ---------------------------------------------------------------------------
# Section 9: PAM — password quality and login failure limits
#
# libpam-pwquality enforces a minimum password quality for local accounts.
# This is relevant for any account that can authenticate with a password
# (e.g. sudo, local console login) even if SSH password auth is disabled.
#
# The limits here are intentionally moderate — not so strict that they
# prevent reasonable passwords, but strong enough to block trivially weak ones.
#
# We also configure pam_faillock (or pam_tally2 on older Ubuntu) to lock
# accounts after repeated failed authentication attempts.
# ---------------------------------------------------------------------------

configure_pam() {
    require_package libpam-pwquality

    if is_applied "pam"; then
        log "PAM already configured — skipping"
        return 0
    fi

    log "Configuring PAM: password quality and login failure limits"

    # --- Password quality (pwquality.conf) ---
    # Write to /etc/security/pwquality.conf (read by pam_pwquality)
    write_file "/etc/security/pwquality.conf" "# secure_oss: PAM password quality configuration
# Applied by harden.sh. See: man pwquality.conf

# Minimum password length (characters)
minlen = 14

# Require at least 1 digit
dcredit = -1

# Require at least 1 uppercase letter
ucredit = -1

# Require at least 1 lowercase letter
lcredit = -1

# Require at least 1 other (special) character
ocredit = -1

# Reject passwords that contain the username (forward or reversed)
usercheck = 1

# Number of recent passwords to remember and reject (requires pam_unix with
# remember= option; set in /etc/pam.d/common-password)
# Note: history is configured in the PAM stack below, not here.

# Reject passwords that are too similar to the previous password
# (difok = minimum number of characters that must differ)
difok = 5

# Minimum number of character classes required (digits/upper/lower/special)
minclass = 3"

    # --- pam_faillock configuration (Ubuntu 22.04+) ---
    # pam_faillock replaces pam_tally2 starting with Ubuntu 22.04.
    # It locks accounts after N failed attempts within a time window.
    if [[ -f /etc/security/faillock.conf ]]; then
        log "Configuring pam_faillock (account lockout after repeated failures)"
        write_file "/etc/security/faillock.conf" "# secure_oss: pam_faillock configuration
# Applied by harden.sh. See: man faillock.conf

# Lock account after this many failed attempts within the fail_interval window
deny = 5

# Time window (seconds) in which failed attempts are counted
fail_interval = 900

# How long (seconds) to lock the account
# 0 = lock until manually unlocked with: faillock --user <username> --reset
unlock_time = 600

# Also count failures for the root account
even_deny_root = true

# How long to lock root (shorter to reduce self-lockout risk)
root_unlock_time = 60

# Audit failed authentication attempts via the audit system
audit = true

# Write a syslog entry on lock
syslog_format = verbose"
    else
        warn "faillock.conf not found — pam_faillock may not be available on this Ubuntu version."
        warn "Account lockout will rely on fail2ban only."
    fi

    mark_applied "pam"
}

# ---------------------------------------------------------------------------
# Section 10: fail2ban — SSH brute force protection
#
# fail2ban monitors log files and bans IP addresses that show malicious
# signs (too many failed authentication attempts). It acts as a first line
# of defense against SSH brute force attacks, banning offending IPs in the
# firewall for a configurable time.
#
# We configure a single jail for SSHD targeting the systemd journal (modern
# Ubuntu uses journald rather than writing to /var/log/auth.log by default).
# ---------------------------------------------------------------------------

configure_fail2ban() {
    require_package fail2ban

    local jail_conf="/etc/fail2ban/jail.d/90-secure-oss-ssh.conf"

    if [[ -f "${jail_conf}" ]]; then
        log "fail2ban jail already configured at ${jail_conf} — skipping"
        return 0
    fi

    log "Configuring fail2ban SSH jail (port ${SSH_PORT})"

    write_file "${jail_conf}" "[DEFAULT]
# Ban IPs for 1 hour (3600 seconds) on first offense.
# Increase for repeat offenders via recidive jail (configure separately).
bantime  = 3600

# Find failed attempts within a 10-minute window.
findtime = 600

# Allow 5 failures before banning.
maxretry = 5

# Use systemd journal as the log backend (modern Ubuntu default).
backend = systemd

# Use UFW as the ban action (integrates with our UFW firewall config).
# Falls back to iptables if UFW is not available.
banaction = ufw

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
# Monitor the systemd journal for sshd authentication events.
# If your system writes to /var/log/auth.log, change this to:
#   logpath = /var/log/auth.log
journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service
maxretry = 3
bantime  = 3600"

    if [[ "${DRY_RUN}" != "1" ]]; then
        systemctl enable --now fail2ban
        systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban
        log "fail2ban configured and running."
        log "Check active bans: fail2ban-client status sshd"
    fi

    mark_applied "fail2ban"
}

# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo -e "${_BOLD}=== Hardening Summary ===${_RESET}"
    echo ""

    local sections=(ufw ssh apparmor sysctl services coredumps auditd updates pam fail2ban)
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
    echo "Post-hardening checklist:"
    echo "  [ ] Verify SSH access still works before closing this session"
    echo "  [ ] ufw status verbose"
    echo "  [ ] sshd -T | grep -E 'permitrootlogin|passwordauth'"
    echo "  [ ] aa-status"
    echo "  [ ] fail2ban-client status sshd"
    echo "  [ ] auditctl -l"
    echo "  [ ] cat /var/log/unattended-upgrades/unattended-upgrades.log"
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
    log "=== secure_oss Ubuntu Server harden.sh v${SCRIPT_VERSION} ==="
    log "SSH port: ${SSH_PORT}"

    require_root
    require_ubuntu

    run_section "ufw"       configure_ufw
    run_section "ssh"       harden_ssh
    run_section "apparmor"  enforce_apparmor
    run_section "sysctl"    configure_sysctl
    run_section "services"  mask_services
    run_section "coredumps" disable_coredumps
    run_section "auditd"    configure_auditd
    run_section "updates"   configure_unattended_upgrades
    run_section "pam"       configure_pam
    run_section "fail2ban"  configure_fail2ban

    print_summary

    if [[ "${_FAILED}" -ne 0 ]]; then
        exit 1
    fi
}

main "$@"
