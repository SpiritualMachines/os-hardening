#!/usr/bin/env bash
# harden.sh — Harden Ubuntu Desktop
#
# Platform  : Ubuntu Desktop 22.04 LTS / 24.04 LTS (GNOME)
# Purpose   : Applies practical security baseline: firewall, AppArmor, sysctl,
#             service masking, core dump disabling, auditd, automatic updates,
#             PAM controls, Ubuntu telemetry blocking, MDM enrollment blocking,
#             and GNOME privacy hardening.
# Tested on : Ubuntu Desktop 22.04 LTS, Ubuntu Desktop 24.04 LTS
# Requires  : root, provision.sh must be run first
#
# Usage:
#   sudo bash harden.sh [--dry-run] [--skip SECTIONS] [--mask-cups]
#
# Options:
#   --skip SECTIONS   Comma-separated list of sections to skip
#   --mask-cups       Also mask cups.service (pass if you don't need printing)
#
# Sections:
#   ufw          — UFW default-deny inbound; no SSH rule (openssh-server not installed by default)
#   apparmor     — Enforce AppArmor profiles for all installed services
#   sysctl       — Network stack and kernel hardening parameters
#   services     — Mask crash reporters, geoclue, gnome-remote-desktop, tracker miners
#   ssh          — Only applies if openssh-server is installed; hardens sshd_config
#   coredumps    — Disable core dump creation system-wide
#   auditd       — Configure audit rules for authentication, file access, privilege use
#   updates      — Configure unattended-upgrades for security-only auto-patching
#   pam          — Password quality requirements and login failure limits
#   telemetry    — Block Ubuntu/Canonical telemetry domains; disable MOTD news; NM connectivity check
#   mdm          — Block MDM/RMM domains; mask landscape-client if present
#   gnome        — GNOME service masking, privacy gsettings, dconf locks
#
# Verification:
#   UFW         : ufw status verbose
#   AppArmor    : aa-status
#   Sysctl      : sysctl net.ipv4.conf.all.accept_redirects kernel.dmesg_restrict
#   Services    : systemctl is-enabled whoopsie.service gnome-remote-desktop.service
#   Coredumps   : ulimit -c (should show 0); sysctl fs.suid_dumpable
#   Auditd      : auditctl -l; systemctl status auditd
#   Updates     : cat /etc/apt/apt.conf.d/50unattended-upgrades
#   PAM         : grep -r pwquality /etc/pam.d/common-password
#   Telemetry   : grep connectivity-check.ubuntu.com /etc/hosts
#   MDM         : grep manage.microsoft.com /etc/hosts
#   GNOME       : gsettings get org.gnome.desktop.privacy report-technical-problems

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

SKIP_SECTIONS=()
MASK_CUPS=0
_SECTIONS_APPLIED=0   # track whether any section ran (for reboot notice)

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: sudo bash harden.sh [OPTIONS]

Apply security hardening to Ubuntu Desktop. Run provision.sh first.

Options:
  --skip SECTIONS   Comma-separated sections to skip:
                    ufw, apparmor, sysctl, services, ssh, coredumps,
                    auditd, updates, pam, telemetry, mdm, gnome
  --mask-cups       Also mask cups.service and cups.socket (disables printing)
  --dry-run         Show what would be done without making changes
  --help            Show this help

Examples:
  sudo bash harden.sh
  sudo bash harden.sh --mask-cups
  sudo bash harden.sh --skip gnome,telemetry
  sudo bash harden.sh --dry-run
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
            --mask-cups)
                MASK_CUPS=1
                shift
                ;;
            *)
                die "Unknown argument: $1. Run with --help for usage."
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Section: ufw — default-deny inbound firewall
#
# UFW's default policy after a fresh Ubuntu Desktop install allows all traffic.
# We flip to default-deny inbound so only explicitly whitelisted ports accept
# connections. Outbound is left unrestricted so the desktop can reach package
# repos, NTP, and web services normally.
#
# Unlike the server script, we do NOT open an SSH port by default. Desktop
# systems do not ship with openssh-server. If the user installs openssh-server,
# the ssh section below will open the appropriate port.
# ---------------------------------------------------------------------------

configure_ufw() {
    require_package ufw

    if is_applied "ufw"; then
        log "UFW already configured — skipping (delete ${MARKER_DIR}/ufw to re-apply)"
        return 0
    fi

    log "Configuring UFW: default deny inbound, allow established outbound"

    run_cmd ufw --force default deny incoming
    run_cmd ufw --force default allow outgoing

    # Allow outbound traffic for established connections (stateful rule)
    run_cmd ufw --force default allow routed

    # Enable UFW (--force suppresses the interactive prompt)
    run_cmd ufw --force enable

    log "UFW enabled. Default: deny inbound, allow outbound."
    log "SSH is NOT opened by default (openssh-server not installed on desktop)."
    log "The 'ssh' section will open the SSH port if openssh-server is detected."
    log "To allow additional services manually: ufw allow <PORT>/tcp"

    mark_applied "ufw"
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: apparmor — enforce profiles for installed services
#
# Ubuntu ships AppArmor enabled by default, but some profiles may be in
# complain mode (log violations without blocking). We flip all loaded
# profiles to enforce mode.
#
# AppArmor confines processes to a defined set of permitted operations.
# A compromised application running under an enforced profile cannot access
# files or make syscalls outside its profile, limiting damage from a compromise.
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

    if ! aa-status --enabled 2>/dev/null; then
        warn "AppArmor is not enabled in the kernel. Check boot parameters (apparmor=1 security=apparmor)."
        return 1
    fi

    log "Setting all AppArmor profiles to enforce mode..."

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would run: aa-enforce /etc/apparmor.d/*"
        return 0
    fi

    local enforced=0
    local failed=0
    for profile in /etc/apparmor.d/*; do
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

    systemctl reload apparmor 2>/dev/null || true

    mark_applied "apparmor"
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: sysctl — network stack and kernel hardening
#
# We install the lib/sysctl-hardening.conf file which contains conservative,
# desktop-appropriate hardening parameters sourced from KSPP, secureblue,
# Kicksecure, and GrapheneOS.
#
# Parameters that do not exist on a given kernel version are tolerated: sysctl
# --system processes the file and skips unknown keys with a warning.
#
# kernel.unprivileged_userns_clone is intentionally absent: Ubuntu 24.04
# removed this sysctl. Chrome, Electron, and container runtimes require user
# namespaces; AppArmor provides the equivalent restriction on 24.04.
# ---------------------------------------------------------------------------

configure_sysctl() {
    local conf_src="${SCRIPT_DIR}/lib/sysctl-hardening.conf"
    local conf_dst="/etc/sysctl.d/90-secure-oss.conf"

    if [[ ! -f "${conf_src}" ]]; then
        die "sysctl config source not found: ${conf_src}"
    fi

    if [[ -f "${conf_dst}" ]]; then
        log "sysctl config already present at ${conf_dst} — skipping"
        log "Delete ${conf_dst} and re-run to regenerate."
        return 0
    fi

    log "Installing sysctl hardening config to ${conf_dst}"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would copy ${conf_src} to ${conf_dst}"
        echo "[DRY RUN] Would run: sysctl --system"
        return 0
    fi

    cp "${conf_src}" "${conf_dst}"

    log "Applying sysctl parameters immediately..."
    # sysctl --system processes all files in /etc/sysctl.d/ and /usr/lib/sysctl.d/
    # Individual keys that don't exist on this kernel version will be skipped.
    sysctl --system 2>&1 | grep --fixed-strings "90-secure-oss" || \
        sysctl -p "${conf_dst}" 2>&1 || \
        warn "Could not apply immediately — parameters will take effect on next reboot"

    mark_applied "sysctl"
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: services — mask unnecessary / privacy-violating services
#
# whoopsie          Ubuntu crash submission service. Sends crash reports to
#                   errors.ubuntu.com. Removed by provision.sh; masked here
#                   as belt-and-suspenders in case it lingers.
#
# kerneloops        Kernel oops submission service. Pure telemetry.
#
# apport            Ubuntu crash handler / bug reporter. Intercepted crashes
#                   can contain sensitive memory contents.
#
# geoclue           Location services daemon. Masked to prevent apps from
#                   obtaining location data via the portal.
#
# gnome-remote-desktop
#                   Provides RDP/VNC remote access to the GNOME desktop.
#                   Masked at the system level; user toggle is locked via dconf.
#
# tracker-miner-*   File indexing miners for GNOME Search. Read all files and
#                   metadata; disabled to reduce attack surface.
#
# cups / cups-browsed
#                   Printing services. Only masked if --mask-cups is passed.
#                   cups-browsed had a critical RCE vulnerability (CVE-2024-47176).
#                   Most desktop users need printing; we leave it enabled by default.
# ---------------------------------------------------------------------------

mask_services() {
    local services_to_mask=(
        "whoopsie.service:Ubuntu crash report submission — sends data to errors.ubuntu.com"
        "whoopsie.socket:whoopsie socket activation"
        "kerneloops.service:Kernel oops submission — pure telemetry"
        "apport.service:Ubuntu crash handler — can expose process memory"
        "geoclue.service:Location services — prevents app access to GPS/WiFi location"
        "gnome-remote-desktop.service:GNOME RDP/VNC remote desktop"
        "tracker-miner-fs-3.service:GNOME file indexing miner — reads all files"
        "tracker-miner-rss-3.service:GNOME RSS indexing miner"
    )

    # cups is only masked when explicitly requested, because printing is
    # a common daily use case on desktop systems. cups-browsed is always
    # masked regardless: CVE-2024-47176 showed it is an unnecessary attack
    # surface (it listens on UDP 631 and accepts printer announcements from the LAN).
    if [[ "${MASK_CUPS}" -eq 1 ]]; then
        services_to_mask+=(
            "cups.service:Printing service (--mask-cups requested)"
            "cups.socket:Printing socket activation"
        )
        log "cups masking enabled via --mask-cups"
    else
        log "cups NOT masked (printing kept enabled; pass --mask-cups to disable)"
    fi

    # cups-browsed is always masked regardless of --mask-cups: it auto-discovers
    # printers on the LAN via UDP/631 and has a history of critical CVEs.
    services_to_mask+=(
        "cups-browsed.service:CUPS network printer discovery — CVE-2024-47176; unnecessary attack surface"
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
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: ssh — sshd_config hardening (conditional)
#
# Desktop systems do not ship with openssh-server by default. This section
# is a no-op if the package is not installed. If openssh-server IS installed
# (e.g. the user enabled it manually), we apply the same hardened config as
# the Ubuntu Server script and add a UFW rule to allow the SSH port.
#
# The same hardening settings apply as the server:
#   PermitRootLogin no, PasswordAuthentication conditional, MaxAuthTries 3,
#   algorithm restrictions, etc.
# ---------------------------------------------------------------------------

harden_ssh() {
    # Only apply if openssh-server is installed
    if ! dpkg-query -W -f='${Status}' openssh-server 2>/dev/null | grep --quiet "install ok installed"; then
        log "openssh-server is not installed — skipping SSH hardening"
        log "If you install openssh-server later, re-run: sudo bash harden.sh --skip ufw,apparmor,sysctl,services,coredumps,auditd,updates,pam,telemetry,mdm,gnome"
        return 0
    fi

    local drop_in="/etc/ssh/sshd_config.d/90-secure-oss.conf"

    if [[ -f "${drop_in}" ]]; then
        log "SSH drop-in already present at ${drop_in} — skipping"
        log "Delete ${drop_in} and re-run to regenerate."
        return 0
    fi

    # Resolve the current SSH port for UFW rule
    local ssh_port
    ssh_port="$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')"
    ssh_port="${ssh_port:-22}"
    log "Detected SSH port: ${ssh_port}"

    # Determine whether it is safe to disable password authentication.
    # Check for any authorized_keys file for a non-root account.
    local disable_password_auth="yes"
    local password_auth_reason=""

    local keys_found=0
    while IFS= read -r -d '' authkeys_file; do
        if [[ -s "${authkeys_file}" ]]; then
            keys_found=1
            break
        fi
    done < <(find /home /root -maxdepth 3 -name "authorized_keys" -print0 2>/dev/null)

    if [[ "${keys_found}" -eq 0 ]]; then
        disable_password_auth="yes"
        password_auth_reason="(no authorized_keys found — leaving password auth ENABLED for safety)"
        warn "==========================================================="
        warn "  SSH key-based auth NOT detected."
        warn "  PasswordAuthentication will NOT be disabled."
        warn "  To disable it manually after adding your SSH key:"
        warn "    Edit ${drop_in}"
        warn "    Change: PasswordAuthentication yes -> no"
        warn "    Then: systemctl reload ssh"
        warn "==========================================================="
    else
        disable_password_auth="no"
        password_auth_reason="(authorized_keys found — safe to disable)"
    fi

    log "SSH PasswordAuthentication: ${disable_password_auth} ${password_auth_reason}"

    write_file "${drop_in}" "# secure_oss: SSH hardening drop-in for Ubuntu Desktop
# Applied by harden.sh — takes precedence over /etc/ssh/sshd_config
# See: man sshd_config

# --- Authentication ---

# Never permit root to log in directly via SSH.
PermitRootLogin no

# Key-based authentication only. See WARNING in harden.sh.
PasswordAuthentication ${disable_password_auth}

# Never accept accounts with no password set.
PermitEmptyPasswords no

# Explicitly enable public key authentication.
PubkeyAuthentication yes

# Accept only public key authentication.
AuthenticationMethods publickey

# --- Brute force mitigation ---

MaxAuthTries 3
LoginGraceTime 30

# --- Session management ---

ClientAliveInterval 300
ClientAliveCountMax 2

# --- Attack surface reduction ---

X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no

# --- Informational ---

PrintLastLog yes
Banner /etc/issue.net

# --- Cryptographic algorithm restrictions ---

KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
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

    # Open the SSH port in UFW so the hardened sshd is reachable
    if ufw status | grep --quiet "Status: active"; then
        log "UFW is active — adding allow rule for SSH port ${ssh_port}/tcp"
        run_cmd ufw allow "${ssh_port}/tcp" comment "SSH (secure_oss)"
    else
        warn "UFW is not active. SSH port ${ssh_port}/tcp not added to firewall rules."
        warn "Run the 'ufw' section first, then re-run the 'ssh' section."
    fi

    mark_applied "ssh"
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: coredumps — disable system-wide
#
# Core dumps can contain the full memory contents of a process at crash time,
# including encryption keys, credentials, session tokens, and private data.
# Three layers of disabling:
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
    # fs.suid_dumpable is also set in sysctl-hardening.conf; applied here
    # defensively in case the sysctl section was skipped.
    if ! grep --quiet "fs.suid_dumpable" /etc/sysctl.d/90-secure-oss.conf 2>/dev/null; then
        append_block \
            "/etc/sysctl.d/90-secure-oss.conf" \
            "### BEGIN secure_oss COREDUMPS SYSCTL ###" \
            "### END secure_oss COREDUMPS SYSCTL ###" \
            "# Prevent setuid/setgid programs from creating core dumps.
fs.suid_dumpable = 0"

        if [[ "${DRY_RUN}" != "1" ]]; then
            sysctl -w fs.suid_dumpable=0 2>/dev/null || true
        fi
    fi

    if [[ "${DRY_RUN}" != "1" ]]; then
        systemctl daemon-reload
    fi

    mark_applied "coredumps"
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: auditd — configure audit rules
#
# The Linux Audit system records security-relevant events at the kernel level.
# These rules log authentication, sensitive file access, privilege escalation,
# network configuration changes, and kernel module activity.
# ---------------------------------------------------------------------------

configure_auditd() {
    require_package auditd

    local rules_file="/etc/audit/rules.d/90-secure-oss.rules"

    if [[ -f "${rules_file}" ]]; then
        log "auditd rules already present at ${rules_file} — skipping"
        log "Delete ${rules_file} and run 'augenrules --load' to regenerate."
        return 0
    fi

    write_file "${rules_file}" "## secure_oss audit rules — Ubuntu Desktop
## Applied by harden.sh. Compiled via: augenrules --load

# ===========================================================================
# Audit system configuration
# ===========================================================================

# Delete all existing rules before loading these (ensures clean state)
-D

# Set the audit buffer size
-b 8192

# Failure mode: 1 = print failure message and continue
-f 1

# ===========================================================================
# Authentication and session management
# ===========================================================================

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

-w /etc/passwd -p wa -k passwd_change
-w /etc/shadow -p wa -k shadow_change
-w /etc/group -p wa -k group_change
-w /etc/gshadow -p wa -k gshadow_change
-w /etc/security/opasswd -p wa -k opasswd_change

# SSH configuration changes (relevant if openssh-server is installed)
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

-a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -k ownership_change
-a always,exit -F arch=b32 -S chown -S fchown -S lchown -S fchownat -k ownership_change
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k permission_change
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k permission_change

# Log use of setuid/setgid executables
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid_exec
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid_exec

# ===========================================================================
# Network and firewall configuration changes
# ===========================================================================

-w /sbin/iptables -p x -k iptables_exec
-w /sbin/ip6tables -p x -k ip6tables_exec
-w /usr/sbin/nft -p x -k nftables_exec
-w /sbin/ip -p x -k ip_exec
-w /etc/network/ -p wa -k network_config
-w /etc/netplan/ -p wa -k netplan_config

# ===========================================================================
# Kernel module loading
# ===========================================================================

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
# Comment this out during initial setup if you need to reload rules without
# rebooting while tuning the configuration.
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
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: updates — unattended-upgrades for security-only auto-patching
#
# Configures automatic installation of security updates only. Non-security
# updates are not applied automatically. Security patches are applied to close
# known vulnerabilities before they are exploited.
# ---------------------------------------------------------------------------

configure_unattended_upgrades() {
    require_package unattended-upgrades

    local conf_file="/etc/apt/apt.conf.d/50unattended-upgrades"

    if is_applied "updates"; then
        log "unattended-upgrades already configured — skipping"
        return 0
    fi

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
// Test them before applying on a production system.

// Remove unused automatically-installed kernel packages.
Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";

// Remove unused dependencies after upgrade.
Unattended-Upgrade::Remove-Unused-Dependencies \"true\";

// Do not auto-reboot on desktop — the user controls when to reboot.
// Change to true and set a time if you want automatic reboots.
Unattended-Upgrade::Automatic-Reboot \"false\";
// Unattended-Upgrade::Automatic-Reboot-Time \"02:00\";

// Send email on upgrade errors (requires a configured MTA).
Unattended-Upgrade::Mail \"\";
Unattended-Upgrade::MailReport \"on-change\";

Unattended-Upgrade::MinimalSteps \"true\";
Unattended-Upgrade::SyslogEnable \"true\";"

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
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: pam — password quality and login failure limits
#
# libpam-pwquality enforces minimum password quality for local accounts.
# pam_faillock (Ubuntu 22.04+) locks accounts after repeated auth failures.
# ---------------------------------------------------------------------------

configure_pam() {
    require_package libpam-pwquality

    if is_applied "pam"; then
        log "PAM already configured — skipping"
        return 0
    fi

    log "Configuring PAM: password quality and login failure limits"

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

# Reject passwords that are too similar to the previous password
difok = 5

# Minimum number of character classes required (digits/upper/lower/special)
minclass = 3"

    # pam_faillock replaces pam_tally2 starting with Ubuntu 22.04
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
    fi

    mark_applied "pam"
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: telemetry — block Ubuntu/Canonical telemetry domains
#
# Appends 0.0.0.0 entries for known telemetry domains to /etc/hosts.
# This null-routes DNS lookups for these domains at the OS level, regardless
# of browser or application settings.
#
# Also:
#   - Disables the motd-news.timer (fetches Ubuntu promotional MOTD content)
#   - Writes a NetworkManager config to disable connectivity checks
#     (NM periodically contacts connectivity-check.ubuntu.com; this is
#     separate from the /etc/hosts block and handles cases where NM resolves
#     via its own DNS cache before /etc/hosts is consulted)
#   - Masks ubuntu-report.service/timer if present
# ---------------------------------------------------------------------------

_apply_hosts_block() {
    local list_file="$1"
    local block_marker="$2"

    if [[ ! -f "${list_file}" ]]; then
        warn "Host block list not found: ${list_file}"
        return 1
    fi

    # Build a "0.0.0.0 DOMAIN" formatted block from the list file,
    # skipping comment lines and blank lines.
    local hosts_content=""
    while IFS= read -r line; do
        # Strip inline comments and leading/trailing whitespace
        line="${line%%#*}"
        line="${line// /}"
        line="${line//	/}"
        if [[ -z "${line}" ]]; then
            continue
        fi
        hosts_content+="0.0.0.0 ${line}"$'\n'
    done < "${list_file}"

    if [[ -z "${hosts_content}" ]]; then
        warn "No valid entries found in ${list_file}"
        return 0
    fi

    append_block \
        "/etc/hosts" \
        "### BEGIN secure_oss ${block_marker} BLOCK — DO NOT EDIT ###" \
        "### END secure_oss ${block_marker} BLOCK ###" \
        "${hosts_content}"
}

block_telemetry() {
    local telemetry_list="${SCRIPT_DIR}/lib/hosts-telemetry.txt"

    log "Blocking telemetry domains in /etc/hosts"
    _apply_hosts_block "${telemetry_list}" "TELEMETRY"

    # Disable the motd-news timer. update-motd.d/50-motd-news fetches content
    # from motd.ubuntu.com and sends Ubuntu version/ESM status in the request.
    # The /etc/hosts block covers the domain, but disabling the timer is cleaner.
    if systemctl cat motd-news.timer &>/dev/null 2>&1; then
        log "Disabling motd-news.timer (MOTD news fetch from Canonical)"
        run_cmd systemctl disable --now motd-news.timer 2>/dev/null || true
    else
        log "motd-news.timer not present — skipping"
    fi

    # Configure NetworkManager to skip connectivity checks. NM contacts
    # connectivity-check.ubuntu.com by default; setting an empty URI disables it.
    # This is belt-and-suspenders alongside the /etc/hosts block: NM may cache
    # the DNS result or bypass /etc/hosts in some configurations.
    log "Disabling NetworkManager connectivity check"
    write_file "/etc/NetworkManager/conf.d/99-no-connectivity-check.conf" \
"# secure_oss: disable NetworkManager connectivity check.
# NM periodically contacts connectivity-check.ubuntu.com to test internet
# access, sending the Ubuntu version and OS information. Setting an empty
# URI disables the check entirely. The UI 'connected' indicator will no
# longer distinguish between 'online' and 'captive portal' states.
[connectivity]
uri="

    # Reload NetworkManager to pick up the new config.
    # On a desktop with an active NM session this is safe; NM restarts gracefully.
    if [[ "${DRY_RUN}" != "1" ]]; then
        if systemctl is-active NetworkManager &>/dev/null; then
            log "Reloading NetworkManager to apply connectivity check config"
            systemctl reload NetworkManager 2>/dev/null || \
                systemctl restart NetworkManager 2>/dev/null || \
                warn "Could not reload NetworkManager — change takes effect on next restart"
        fi
    fi

    # Mask ubuntu-report.service and timer if present. ubuntu-report sends
    # hardware/software configuration data to Canonical on first boot.
    for unit in ubuntu-report.service ubuntu-report.timer; do
        if systemctl cat "${unit}" &>/dev/null 2>&1; then
            log "Masking ${unit} (Ubuntu system report submission)"
            run_cmd systemctl mask "${unit}" 2>/dev/null || true
            run_cmd systemctl stop "${unit}" 2>/dev/null || true
        fi
    done

    mark_applied "telemetry"
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: mdm — block MDM/RMM enrollment domains
#
# Appends 0.0.0.0 entries for known MDM and RMM infrastructure domains.
# This prevents enrollment clients, agents, and management tools from
# reaching their cloud backends even if installed by a third party.
#
# Also masks landscape-client if present: Canonical Landscape is a remote
# management platform for Ubuntu systems. Users who want Landscape can
# unmask it; the default is to prevent it from running.
# ---------------------------------------------------------------------------

block_mdm() {
    local mdm_list="${SCRIPT_DIR}/lib/hosts-mdm.txt"

    log "Blocking MDM/RMM domains in /etc/hosts"
    _apply_hosts_block "${mdm_list}" "MDM"

    # landscape-client connects to landscape.canonical.com (or a self-hosted
    # Landscape server) to receive management commands. On a personal desktop
    # this is equivalent to an RMM agent that can execute arbitrary commands.
    if systemctl cat landscape-client.service &>/dev/null 2>&1; then
        log "Masking landscape-client.service (Canonical Landscape remote management)"
        run_cmd systemctl mask landscape-client.service
        run_cmd systemctl stop landscape-client.service 2>/dev/null || true
    else
        log "landscape-client.service not present — skipping"
    fi

    mark_applied "mdm"
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Section: gnome — GNOME privacy hardening
#
# Sources lib/gnome.sh which provides:
#   gnome_harden_services     — mask gnome-remote-desktop, geoclue, trackers,
#                               whoopsie, kerneloops, apport (belt-and-suspenders)
#   gnome_harden_user_settings — gsettings privacy, lock screen, notifications
#   gnome_apply_dconf_locks   — system-level dconf policy locks
#
# NOTE: gsettings requires a running D-Bus session bus to be effective. If
# this script is run from a TTY (not from within a GNOME session), user-level
# gsettings may not apply. In that case, re-run from the desktop session:
#   sudo bash harden.sh --skip ufw,apparmor,sysctl,services,ssh,coredumps,auditd,updates,pam,telemetry,mdm
# ---------------------------------------------------------------------------

harden_gnome_section() {
    # Source the GNOME hardening library
    # shellcheck source=lib/gnome.sh
    source "${SCRIPT_DIR}/lib/gnome.sh"

    # Detect the desktop environment
    detect_desktop_environment

    if [[ "${DE}" != "gnome" ]]; then
        warn "Desktop environment is not GNOME (detected: '${DE}')."
        warn "GNOME-specific hardening skipped."
        return 0
    fi

    # Warn if we may not have access to the user's D-Bus session.
    # DBUS_SESSION_BUS_ADDRESS is set when running inside a session; if absent
    # (e.g. plain root login or cron), gsettings will fail silently.
    local target_user
    target_user="$(get_sudo_user 2>/dev/null)" || true

    if [[ -n "${target_user}" ]]; then
        local user_bus
        user_bus="$(sudo --user="${target_user}" \
            --preserve-env=HOME,XDG_RUNTIME_DIR,DBUS_SESSION_BUS_ADDRESS \
            bash -c 'echo "${DBUS_SESSION_BUS_ADDRESS:-}"' 2>/dev/null || echo "")"

        if [[ -z "${user_bus}" ]]; then
            warn "D-Bus session bus not detected for user '${target_user}'."
            warn "User-level gsettings may not apply if run outside a GNOME session."
            warn "dconf locks and service masking will still be applied."
            warn "To apply gsettings, log in as ${target_user} and re-run:"
            warn "  sudo bash ${SCRIPT_DIR}/harden.sh --skip ufw,apparmor,sysctl,services,ssh,coredumps,auditd,updates,pam,telemetry,mdm"
        fi
    fi

    harden_gnome

    mark_applied "gnome"
    _SECTIONS_APPLIED=1
}

# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo -e "${_BOLD}=== Hardening Summary ===${_RESET}"
    echo ""

    local sections=(ufw apparmor sysctl services ssh coredumps auditd updates pam telemetry mdm gnome)
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
    echo "  [ ] ufw status verbose"
    echo "  [ ] aa-status"
    echo "  [ ] auditctl -l"
    echo "  [ ] sysctl kernel.dmesg_restrict net.ipv4.conf.all.accept_redirects"
    echo "  [ ] grep connectivity-check.ubuntu.com /etc/hosts"
    echo "  [ ] grep manage.microsoft.com /etc/hosts"
    echo "  [ ] gsettings get org.gnome.desktop.privacy report-technical-problems"
    echo "  [ ] systemctl is-enabled whoopsie.service gnome-remote-desktop.service"
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
    log "=== secure_oss Ubuntu Desktop harden.sh v${SCRIPT_VERSION} ==="

    require_root
    require_ubuntu

    run_section "ufw"       configure_ufw
    run_section "apparmor"  enforce_apparmor
    run_section "sysctl"    configure_sysctl
    run_section "services"  mask_services
    run_section "ssh"       harden_ssh
    run_section "coredumps" disable_coredumps
    run_section "auditd"    configure_auditd
    run_section "updates"   configure_unattended_upgrades
    run_section "pam"       configure_pam
    run_section "telemetry" block_telemetry
    run_section "mdm"       block_mdm
    run_section "gnome"     harden_gnome_section

    print_summary

    if [[ "${_SECTIONS_APPLIED}" -eq 1 ]]; then
        reboot_notice "Some settings require a reboot to take full effect"
    fi

    if [[ "${_FAILED}" -ne 0 ]]; then
        exit 1
    fi
}

main "$@"
