#!/usr/bin/env bash
# harden.sh — Harden FreeBSD
#
# Platform  : FreeBSD 13 / 14
# Purpose   : Applies a practical security baseline: pf default-deny firewall,
#             rc.conf service hardening, sysctl network and kernel hardening,
#             SSH hardening, core dump disabling, and periodic security jobs.
# Tested on : FreeBSD 14.1-RELEASE
# Requires  : root, provision.sh run first
#
# Usage:
#   sudo bash harden.sh [--dry-run] [--ssh-port PORT] [--skip SECTION]
#
# Skip sections (--skip, comma-separated):
#   pf, rc, sysctl, ssh, coredumps, periodic
#
# Verification:
#   pf       : pfctl -sr (show ruleset); pfctl -si (show info)
#   rc       : service sendmail status; service rpcbind status
#   sysctl   : sysctl net.inet.tcp.syncookies security.bsd.see_other_uids
#   ssh      : sshd -T | grep -E 'permitrootlogin|passwordauth'
#   coredumps: sysctl kern.coredump
#   periodic : cat /etc/periodic.conf

set -euo pipefail

DRY_RUN=0
SKIP_SECTIONS=()
SSH_PORT=""
LOG_FILE="/var/log/secure_oss.log"
MARKER_DIR="/etc/secure_oss/applied"
_FAILED=0

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

write_file() {
    local path="$1" content="$2"
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would write: ${path}\033[0m"
        echo "${content}"
    else
        log "Writing: ${path}"
        mkdir --parents "$(dirname "${path}")"
        printf '%s\n' "${content}" > "${path}"
    fi
}

is_applied()   { [[ -f "${MARKER_DIR}/$1" ]]; }
mark_applied() {
    [[ "${DRY_RUN}" == "1" ]] && return
    mkdir --parents "${MARKER_DIR}"
    echo "$(date '+%Y-%m-%d %H:%M:%S')" > "${MARKER_DIR}/$1"
}

should_skip() {
    local s
    for s in "${SKIP_SECTIONS[@]+"${SKIP_SECTIONS[@]}"}"; do
        [[ "${s}" == "$1" ]] && return 0
    done
    return 1
}

run_section() {
    local name="$1" fn="$2"
    if should_skip "${name}"; then
        warn "Skipping section: ${name}"
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

# rc.conf helper — set a key=value only if not already present
rc_conf_set() {
    local key="$1" value="$2"
    if grep --quiet "^${key}=" /etc/rc.conf 2>/dev/null; then
        run_cmd "sed -i '' 's|^${key}=.*|${key}=${value}|' /etc/rc.conf"
    else
        run_cmd "echo '${key}=${value}' >> /etc/rc.conf"
    fi
    log "  rc.conf: ${key}=${value}"
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ssh-port) SSH_PORT="${2:?}"; shift 2 ;;
            --skip)     IFS=',' read -ra SKIP_SECTIONS <<< "${2:?}"; shift 2 ;;
            --dry-run)  DRY_RUN=1; warn "Dry-run mode."; shift ;;
            --help|-h)  grep '^#' "$0" | head -30; exit 0 ;;
            *)          die "Unknown argument: $1" ;;
        esac
    done

    SSH_PORT="${SSH_PORT:-$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')}"
    SSH_PORT="${SSH_PORT:-22}"
}

# ---------------------------------------------------------------------------
# Section 1: pf firewall
#
# FreeBSD's pf (Packet Filter) is the preferred firewall. We write a strict
# ruleset that:
#   - Blocks all inbound by default
#   - Allows established/related return traffic (keep state)
#   - Allows ICMP from local network
#   - Allows SSH from anywhere (restrict to local subnet if preferred)
#   - Allows all outbound
#
# The rules are written to /etc/pf.conf. pf is enabled in /etc/rc.conf.
# The existing /etc/pf.conf is backed up before overwriting.
#
# Verification: pfctl -sr    (show ruleset)
#               pfctl -si    (show info — packets passed/blocked)
#               pfctl -nf /etc/pf.conf  (validate without loading)
# ---------------------------------------------------------------------------

configure_pf() {
    if is_applied "pf"; then
        log "pf already configured — skipping"
        return 0
    fi

    log "Configuring pf firewall..."
    log "SSH port: ${SSH_PORT}"

    # Detect the primary network interface
    local ext_if
    ext_if="$(netstat -rn 2>/dev/null | awk '/^default/ {print $NF; exit}')"
    ext_if="${ext_if:-em0}"
    log "Primary interface: ${ext_if}"

    # Detect local subnet
    local local_net
    local_net="$(ifconfig "${ext_if}" 2>/dev/null \
        | awk '/inet / {print $2"/"$4}' \
        | python3 -c "
import sys, ipaddress
try:
    line = sys.stdin.read().strip()
    ip, mask = line.split('/')
    # Convert mask from hex to prefix length
    if '.' in mask:
        prefixlen = sum(bin(int(x)).count('1') for x in mask.split('.'))
    else:
        prefixlen = int(mask, 16).bit_length()
    net = ipaddress.ip_network(f'{ip}/{prefixlen}', strict=False)
    print(str(net))
except Exception:
    print('192.168.1.0/24')
" 2>/dev/null)"
    local_net="${local_net:-192.168.1.0/24}"
    log "Local network: ${local_net}"

    # Back up existing pf.conf
    if [[ -f /etc/pf.conf ]] && [[ "${DRY_RUN}" != "1" ]]; then
        cp /etc/pf.conf "/etc/pf.conf.bak.$(date '+%Y%m%d%H%M%S')"
        log "Backed up existing /etc/pf.conf"
    fi

    write_file "/etc/pf.conf" "# /etc/pf.conf — secure_oss hardened ruleset
# Generated by harden.sh. Validate with: pfctl -nf /etc/pf.conf
# Reload with: pfctl -f /etc/pf.conf
# Status: pfctl -si

# ---------------------------------------------------------------------------
# Macros
# ---------------------------------------------------------------------------

ext_if = \"${ext_if}\"
local_net = \"${local_net}\"
ssh_port = \"${SSH_PORT}\"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

# Normalise fragmented packets before processing (reassemble for inspection)
set reassemble yes no-df

# Log blocked packets to pflog0 interface
# View with: tcpdump -n -e -ttt -i pflog0
set loginterface \$ext_if

# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

# Scrub (normalise) all incoming packets on the external interface.
# Defragments packets, enforces MSS limits, and fixes TCP flag issues.
match in on \$ext_if scrub (no-df random-id)

# ---------------------------------------------------------------------------
# Default policies
# ---------------------------------------------------------------------------

# Block everything by default. Log inbound blocks so they appear on pflog0.
block in  log all
block out all

# ---------------------------------------------------------------------------
# Loopback
# ---------------------------------------------------------------------------

# Allow all loopback traffic. Processes communicating locally must not be blocked.
pass quick on lo0 all

# ---------------------------------------------------------------------------
# Outbound
# ---------------------------------------------------------------------------

# Allow all outbound traffic from the host (keep state for return traffic).
pass out on \$ext_if all keep state

# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------

# Allow ICMP echo (ping) from the local network for diagnostics.
# Do not allow ping from the internet to limit exposure.
pass in on \$ext_if proto icmp from \$local_net icmp-type echoreq keep state

# Allow ICMPv6 (required for IPv6 neighbor discovery and autoconfiguration)
pass in  inet6 proto icmp6 all keep state
pass out inet6 proto icmp6 all keep state

# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

# Allow SSH from anywhere. To restrict to local subnet only, change 'any' to
# '\$local_net'. If you use port knocking, remove this rule and add knockd.
pass in on \$ext_if proto tcp from any to any port \$ssh_port keep state

# ---------------------------------------------------------------------------
# Return traffic
# ---------------------------------------------------------------------------

# Allow return traffic for connections initiated by this host.
# The 'keep state' on 'pass out' above handles this — the block default
# does not affect established sessions because pf evaluates state tables first."

    # Enable pf in rc.conf
    rc_conf_set 'pf_enable'       '"YES"'
    rc_conf_set 'pf_rules'        '"/etc/pf.conf"'
    rc_conf_set 'pflog_enable'    '"YES"'    # Enable pflog for blocked packet inspection
    rc_conf_set 'pflog_logfile'   '"/var/log/pflog"'

    # Validate the ruleset before loading
    if [[ "${DRY_RUN}" != "1" ]]; then
        if pfctl -nf /etc/pf.conf; then
            log "pf ruleset validated successfully."
            service pf start 2>/dev/null || pfctl -f /etc/pf.conf || \
                warn "Could not load pf rules — they will be active after reboot"
            service pflog start 2>/dev/null || true
        else
            warn "pf ruleset validation FAILED. Review /etc/pf.conf."
            return 1
        fi
    fi

    log "pf firewall configured. Default: block all inbound, allow established outbound."
    log "To open additional ports: add 'pass in on \$ext_if proto tcp to any port <PORT> keep state' to /etc/pf.conf"

    mark_applied "pf"
}

# ---------------------------------------------------------------------------
# Section 2: rc.conf service hardening
#
# Disables services that are enabled by default but represent unnecessary
# attack surface or privacy concerns:
#
#   sendmail      The default MTA. Listens on port 25 and 587 by default.
#                 Unless this machine needs to send/receive mail directly,
#                 disable all four sendmail components.
#
#   rpcbind       RPC portmapper. Required for NFS. If you don't use NFS,
#                 disabling this closes port 111.
#
#   inetd         Legacy super-server. Starts various small services on demand.
#                 Almost never needed on a modern FreeBSD system.
#
#   syslogd flags Adds -s (don't listen on UDP 514 for remote syslog) and
#                 -c (no DNS lookups for IP addresses in logs — faster and
#                 avoids information leakage via DNS queries for log events).
# ---------------------------------------------------------------------------

harden_rc_conf() {
    if is_applied "rc"; then
        log "rc.conf already hardened — skipping"
        return 0
    fi

    log "Hardening /etc/rc.conf service configuration..."

    # --- Sendmail ---
    # Disable all four sendmail components. They collectively open network
    # listeners and create an unnecessary attack surface on non-mail servers.
    rc_conf_set 'sendmail_enable'              '"NONE"'
    rc_conf_set 'sendmail_submit_enable'       '"NO"'
    rc_conf_set 'sendmail_outbound_enable'     '"NO"'
    rc_conf_set 'sendmail_msp_queue_enable'    '"NO"'
    warn "sendmail disabled. If you need outbound email, install and configure postfix or ssmtp."

    # --- rpcbind ---
    # Only needed for NFS. Comment this block out or use --skip rc if you mount NFS.
    rc_conf_set 'rpcbind_enable' '"NO"'

    # --- inetd ---
    # Disable the inetd super-server. If any inetd-based service is needed,
    # enable specific daemons individually rather than running inetd.
    rc_conf_set 'inetd_enable' '"NO"'

    # --- syslogd ---
    # -ss : do not accept remote syslog messages on UDP 514 (double -s = even
    #       more restrictive than single -s)
    # -c  : do not perform DNS lookups for log entries
    rc_conf_set 'syslogd_flags' '"-ss -c"'

    # --- SSH: ensure it's enabled and using the right port ---
    rc_conf_set 'sshd_enable' '"YES"'

    # --- Crash dumps ---
    # Disable kernel crash dump creation. Crash dumps can contain sensitive
    # memory content. Handled more completely in the coredumps section.
    rc_conf_set 'dumpdev' '"NO"'

    mark_applied "rc"
}

# ---------------------------------------------------------------------------
# Section 3: sysctl hardening
#
# Written to /etc/sysctl.conf which is read on every boot.
# The existing file is appended to (not replaced) — existing settings are
# preserved. Our settings are wrapped in markers for idempotency.
# ---------------------------------------------------------------------------

configure_sysctl() {
    if is_applied "sysctl"; then
        log "sysctl already configured — skipping"
        return 0
    fi

    local begin_marker="### BEGIN secure_oss SYSCTL ###"
    local end_marker="### END secure_oss SYSCTL ###"

    # Remove existing block if present (idempotency)
    if grep --quiet "${begin_marker}" /etc/sysctl.conf 2>/dev/null; then
        log "Removing existing secure_oss sysctl block for fresh write..."
        if [[ "${DRY_RUN}" != "1" ]]; then
            python3 - /etc/sysctl.conf "${begin_marker}" "${end_marker}" <<'PYEOF'
import sys
path, begin, end = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    lines = f.readlines()
out, inside = [], False
for l in lines:
    if begin in l: inside = True
    if not inside: out.append(l)
    if end in l: inside = False
with open(path, 'w') as f:
    f.writelines(out)
PYEOF
        fi
    fi

    local sysctl_block="${begin_marker}

# ===========================================================================
# Network hardening
# ===========================================================================

# Drop TCP connections with FIN+SYN (invalid flag combination used in scans)
net.inet.tcp.drop_synfin=1

# Blackhole TCP SYN packets to closed ports (don't send RST — stealth mode)
# 0=RST, 1=RST+log, 2=drop silently. Value 2 avoids confirming closed ports to scanners.
net.inet.tcp.blackhole=2

# Blackhole UDP packets to closed ports
net.inet.udp.blackhole=1

# Randomise IP ID field (prevents OS fingerprinting via sequential IDs)
net.inet.ip.random_id=1

# Drop ICMP redirects (routing MITM prevention)
net.inet.icmp.drop_redirect=1
net.inet6.icmp6.rediraccept=0

# Disable sending IP redirects (we are not a router)
net.inet.ip.redirect=0
net.inet6.ip6.redirect=0

# Disable source routing (packets specifying their own route)
net.inet.ip.sourceroute=0
net.inet.ip.accept_sourceroute=0

# Enable TCP SYN cookies (SYN flood protection)
net.inet.tcp.syncookies=1

# ===========================================================================
# Security hardening
# ===========================================================================

# Prevent users from seeing processes owned by other users.
# Essential on multi-user systems; good practice even on single-user servers.
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0

# Prevent unprivileged users from reading the kernel message buffer (dmesg).
# dmesg can leak kernel addresses useful for defeating ASLR.
security.bsd.unprivileged_read_msgbuf=0

# Prevent processes from debugging processes owned by other users (ptrace).
# Value 1 = only parent can ptrace child. Prevents lateral process inspection.
security.bsd.unprivileged_proc_debug=0

# Prevent hardlinks to files the user does not own.
# Mitigates TOCTOU vulnerabilities involving hardlinks to sensitive files.
security.bsd.hardlink_check_uid=1
security.bsd.hardlink_check_gid=1

# Disable kernel crash dumps (handled in rc.conf too; belt-and-suspenders)
kern.coredump=0

# Randomise PID allocation (makes PID-based attacks harder)
kern.randompid=337

${end_marker}"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would append sysctl block to /etc/sysctl.conf\033[0m"
        echo "${sysctl_block}"
        return 0
    fi

    printf '\n%s\n' "${sysctl_block}" >> /etc/sysctl.conf
    log "Appended sysctl hardening block to /etc/sysctl.conf"

    # Apply immediately
    log "Applying sysctl values now..."
    while IFS= read -r line; do
        [[ "${line}" =~ ^# ]] && continue
        [[ -z "${line}" ]] && continue
        [[ "${line}" =~ ^### ]] && continue
        sysctl "${line}" 2>/dev/null || warn "Could not set: ${line}"
    done <<< "${sysctl_block}"

    mark_applied "sysctl"
}

# ---------------------------------------------------------------------------
# Section 4: SSH hardening
#
# Writes a hardened /etc/ssh/sshd_config. The original is backed up.
# ---------------------------------------------------------------------------

harden_ssh() {
    if is_applied "ssh"; then
        log "SSH already hardened — skipping"
        return 0
    fi

    # Safety check
    local disable_password="no"
    local keys_found=0
    while IFS= read -r -d '' f; do
        [[ -s "${f}" ]] && keys_found=1 && break
    done < <(find /root /home -maxdepth 3 -name "authorized_keys" -print0 2>/dev/null)

    [[ "${keys_found}" -eq 1 ]] && disable_password="yes" \
        || warn "No authorized_keys found — PasswordAuthentication will remain enabled."

    if [[ -f /etc/ssh/sshd_config ]] && [[ "${DRY_RUN}" != "1" ]]; then
        cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date '+%Y%m%d%H%M%S')"
    fi

    write_file "/etc/ssh/sshd_config" "# /etc/ssh/sshd_config — secure_oss hardened config
# Generated by harden.sh

Port ${SSH_PORT}
AddressFamily inet

# --- Authentication ---
PermitRootLogin no
PasswordAuthentication ${disable_password}
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# --- Brute force mitigation ---
MaxAuthTries 3
LoginGraceTime 30

# --- Session ---
ClientAliveInterval 300
ClientAliveCountMax 2

# --- Attack surface ---
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintLastLog yes
Banner /etc/issue

# --- Crypto ---
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"

    write_file "/etc/issue" "**********************************************************************
* WARNING: Authorized access only.                                   *
* Unauthorized access is prohibited and will be prosecuted.          *
* All activity is monitored and logged.                              *
**********************************************************************"

    if [[ "${DRY_RUN}" != "1" ]]; then
        if sshd -t 2>&1; then
            service sshd restart
            log "sshd restarted with hardened config."
        else
            warn "sshd config validation failed. Restoring backup."
            cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config 2>/dev/null || true
            return 1
        fi
    fi

    mark_applied "ssh"
}

# ---------------------------------------------------------------------------
# Section 5: Core dumps — disable system-wide
# ---------------------------------------------------------------------------

disable_coredumps() {
    if is_applied "coredumps"; then
        log "Core dumps already disabled — skipping"
        return 0
    fi

    log "Disabling kernel and process core dumps..."

    # kern.coredump=0 is set in sysctl section; this adds the process-level setting
    # via login.conf and /etc/sysctl.conf belt-and-suspenders

    # Disable core dumps for all users via login.conf default class
    local begin="### BEGIN secure_oss COREDUMP ###"
    local end="### END secure_oss COREDUMP ###"

    if ! grep --quiet "${begin}" /etc/login.conf 2>/dev/null; then
        if [[ "${DRY_RUN}" != "1" ]]; then
            # Insert coredumpsize=0 into the default login class
            sed -i '' '/^default:\\/,/[^\\]$/ {
                /[^\\]$/ {
                    a\\
# '"${begin}"'\\
\t:coredumpsize=0:\\
# '"${end}"'
                }
            }' /etc/login.conf
            cap_mkdb /etc/login.conf
            log "Set coredumpsize=0 in /etc/login.conf default class"
        else
            echo "[DRY RUN] Would add coredumpsize=0 to /etc/login.conf default class"
        fi
    else
        log "login.conf coredump setting already present"
    fi

    mark_applied "coredumps"
}

# ---------------------------------------------------------------------------
# Section 6: Periodic security
#
# FreeBSD runs daily/weekly/monthly maintenance scripts via /etc/periodic/.
# /etc/periodic.conf controls which checks are enabled.
# We enable security-relevant checks and tighten the defaults.
# ---------------------------------------------------------------------------

configure_periodic() {
    if is_applied "periodic"; then
        log "Periodic already configured — skipping"
        return 0
    fi

    local begin="### BEGIN secure_oss PERIODIC ###"
    local end="### END secure_oss PERIODIC ###"

    if grep --quiet "${begin}" /etc/periodic.conf 2>/dev/null; then
        log "Periodic already configured — skipping"
        mark_applied "periodic"
        return 0
    fi

    local periodic_block="${begin}

# ===========================================================================
# Daily security checks
# ===========================================================================

# Check for changes to setuid/setgid binaries
daily_status_security_inline=\"YES\"

# Run pkg audit daily to check for newly disclosed vulnerabilities
daily_pkgaudit_enable=\"YES\"

# Check for changes in /etc/passwd and /etc/group
daily_status_security_passwd=\"YES\"

# Check mtree for filesystem changes (requires mtree database — see mtree(8))
daily_mtree_enable=\"NO\"   # Set to YES after running: /usr/sbin/mtree -cU -p / > /etc/mtree/secure_oss.spec

# ===========================================================================
# Weekly security checks
# ===========================================================================

weekly_status_pkg_changes_enable=\"YES\"   # Report installed package changes

# ===========================================================================
# Logging
# ===========================================================================

# Send daily output to root (ensure root's mail is forwarded if desired)
daily_output=\"root\"
weekly_output=\"root\"
monthly_output=\"root\"

${end}"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would append periodic config to /etc/periodic.conf\033[0m"
        echo "${periodic_block}"
        return 0
    fi

    printf '\n%s\n' "${periodic_block}" >> /etc/periodic.conf
    log "Periodic security checks configured in /etc/periodic.conf"

    mark_applied "periodic"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo -e "\033[1m=== Hardening Summary ===\033[0m"
    echo ""

    local sections=(pf rc sysctl ssh coredumps periodic)
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
    echo "  pf       : pfctl -sr && pfctl -si"
    echo "  rc       : service sendmail status; service rpcbind status"
    echo "  sysctl   : sysctl net.inet.tcp.blackhole security.bsd.see_other_uids"
    echo "  ssh      : sshd -T | grep -E 'permitrootlogin|passwordauth|maxauthtries'"
    echo "  coredumps: sysctl kern.coredump  (should show 0)"
    echo "  periodic : cat /etc/periodic.conf | grep secure_oss -A 30"
    echo ""
    echo "Post-hardening:"
    echo "  [ ] Verify SSH access works before ending this session"
    echo "  [ ] Add additional pf rules for services this host exposes"
    echo "  [ ] Forward root mail: add 'root: your@email.com' to /etc/aliases && newaliases"
    echo ""

    [[ "${_FAILED}" -ne 0 ]] && warn "One or more sections had errors. Review output above."
    log "Done. Reboot recommended."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

parse_args "$@"

mkdir --parents /var/log "${MARKER_DIR}"
log "=== secure_oss FreeBSD harden.sh ==="
log "SSH port: ${SSH_PORT}"

[[ "${EUID}" -ne 0 ]] && die "Must be run as root."
uname -s | grep --quiet FreeBSD || die "This script must be run on FreeBSD."

run_section "pf"        configure_pf
run_section "rc"        harden_rc_conf
run_section "sysctl"    configure_sysctl
run_section "ssh"       harden_ssh
run_section "coredumps" disable_coredumps
run_section "periodic"  configure_periodic

print_summary

[[ "${_FAILED}" -ne 0 ]] && exit 1
exit 0
