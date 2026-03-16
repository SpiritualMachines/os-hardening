#!/usr/bin/env bash
# optional/forensics-share.sh — Harden an Unraid share used for forensic/incident storage
#
# Platform  : Unraid 6.10+
# Purpose   : Locks down a named Unraid share that stores potentially malicious
#             files (malware samples, forensic images, incident artifacts).
#             The threat model here is INTERNAL: preventing files sitting on
#             disk from being executed, exploiting services that touch them,
#             or escaping into other parts of the system.
# Tested on : Unraid 6.12
# Requires  : root, harden.sh already run
#
# Usage:
#   bash forensics-share.sh --share NAME [OPTIONS]
#
# Options:
#   --share NAME        Unraid share name to protect (e.g. "forensics")
#                       The share must already exist in the Unraid UI.
#   --read-only         Mount the share read-only (noexec + ro). Use this if
#                       you only need to READ files, never write new ones via
#                       the local filesystem. (Samba can still write via its
#                       own path — see note in Samba section.)
#   --dry-run           Show what would be done without making changes
#   --help              Show this help
#
# WHAT THIS SCRIPT DOES
# ---------------------
#
# 1. NOEXEC BIND MOUNT
#    Bind-mounts the share path over itself with noexec, nosuid, nodev.
#    Effect: the Linux kernel will refuse to execute ANY file from this
#    share, regardless of file permissions or who asks. Even root cannot
#    execute a file from a noexec mount. This is the single most important
#    protection when storing malware samples or unknown binaries.
#    Persisted via /boot/config/go so it re-applies after every reboot.
#
# 2. SAMBA SHARE HARDENING
#    Writes share-specific Samba options to /boot/config/smb-extra.conf:
#      follow symlinks = no   — Samba will not follow symlinks within the share.
#                               A malicious symlink pointing to /etc/passwd
#                               cannot be followed, even if the client requests it.
#      wide links = no        — Samba will not follow symlinks that point OUTSIDE
#                               the share root. Without this, a symlink in the
#                               share could expose any file on the host filesystem.
#      read only = yes        — (if --read-only) Prevents writes via Samba at the
#                               protocol level, regardless of filesystem permissions.
#    Note: Unraid generates smb.conf on each Samba restart. These settings are
#    applied via the include mechanism and a go hook that patches the generated
#    config after each Samba reload.
#
# 3. DOCKER CONTAINER AUDIT
#    Scans all running Docker containers for volume mounts that include the
#    forensics share path. Any container with access to the share can read
#    (and potentially be exploited by) the malicious files stored there.
#    Reports findings — does NOT automatically remove mounts (that would
#    require stopping containers and modifying their configs).
#
# 4. MEDIA SERVER EXCLUSION MARKERS
#    Creates marker files that tell common media servers (Plex, Jellyfin,
#    Emby) not to index this directory. Media parsers (FFmpeg, libheif,
#    libraw, etc.) have a long history of parser vulnerabilities exploitable
#    via crafted media files. A media server scanning a directory of malware
#    samples is a genuine risk.
#
# 5. FILESYSTEM PERMISSIONS
#    Sets the share directory ownership to root:root with mode 750, and
#    removes world-readable/executable bits. This prevents the 'nobody'
#    user (which Samba and some Docker containers run as) from reading the
#    share without explicit permission.
#
# THREAT MODEL
# ------------
# This script defends against:
#   - Accidental execution of malware stored on the share
#   - Services auto-parsing files (media servers, indexers, AV engines)
#     being exploited via crafted file content
#   - Symlink-based path traversal from malicious filenames in the share
#   - Docker containers with share access being used as an execution proxy
#   - Network clients requesting execution or symlink traversal via Samba
#
# This script does NOT defend against:
#   - A compromised root process (root can remount noexec)
#   - Network-level attacks (those are handled by the firewall in harden.sh)
#   - Files being COPIED out of the share to a non-noexec location and executed
#   - Kernel exploits triggered by the filesystem driver itself reading the disk
#     (e.g., crafted ext4/xfs metadata — mitigated by not mounting suspect disks
#     directly; use a VM or loopback device with -o noexec,nosuid for disk images)
#
# VERIFICATION
# ------------
#   noexec   : mount | grep <share-path>   (should show "noexec")
#   Samba    : grep -A5 '\[forensics\]' /etc/samba/smb.conf
#   Docker   : docker inspect <container> | grep Mounts -A 20
#   Permissions: ls -la /mnt/user/<share>
#   Test exec: cp /bin/ls /mnt/user/<share>/test_exec && /mnt/user/<share>/test_exec
#              (should fail with "Permission denied")

set -euo pipefail

SHARE_NAME=""
READ_ONLY=0
DRY_RUN=0

LOG_FILE="/var/log/secure_oss_unraid.log"
BOOT_SCRIPTS_DIR="/boot/config/scripts"
GO_FILE="/boot/config/go"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

usage() {
    sed -n '/^# Usage:/,/^# WHAT THIS/{ /^# WHAT/d; s/^# \?//; p }' "$0"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --share)     SHARE_NAME="${2:?--share requires a value}"; shift 2 ;;
            --read-only) READ_ONLY=1; shift ;;
            --dry-run)   DRY_RUN=1; warn "Dry-run mode — no changes will be made."; shift ;;
            --help|-h)   usage; exit 0 ;;
            *)           die "Unknown argument: $1. Run with --help." ;;
        esac
    done

    [[ -z "${SHARE_NAME}" ]] && die "--share NAME is required. Example: --share forensics"
}

# ---------------------------------------------------------------------------
# Patch /boot/config/go (idempotent)
# ---------------------------------------------------------------------------

patch_go_file() {
    local marker="$1" line="$2"
    if grep --quiet --fixed-strings "${marker}" "${GO_FILE}" 2>/dev/null; then
        log "  ${GO_FILE} already contains '${marker}' — skipping"
        return 0
    fi
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would append to ${GO_FILE}: ${line}\033[0m"
        return 0
    fi
    printf '\n# %s\n%s\n' "${marker}" "${line}" >> "${GO_FILE}"
    log "  Patched ${GO_FILE}: ${marker}"
}

# ---------------------------------------------------------------------------
# Step 1: noexec bind mount
# ---------------------------------------------------------------------------

apply_noexec_mount() {
    banner "noexec bind mount"

    local share_path="/mnt/user/${SHARE_NAME}"
    local mount_opts="bind,noexec,nosuid,nodev"
    [[ "${READ_ONLY}" == "1" ]] && mount_opts="${mount_opts},ro"

    if [[ ! -d "${share_path}" ]]; then
        die "Share path does not exist: ${share_path}
Make sure the share '${SHARE_NAME}' exists in the Unraid web UI and the array is started."
    fi

    log "Share path   : ${share_path}"
    log "Mount options: ${mount_opts}"

    # Check if already mounted with noexec
    if mount | grep --quiet "${share_path}.*noexec"; then
        log "${share_path} is already mounted with noexec — skipping live mount"
    else
        # Apply immediately (bind mount over existing path)
        run_cmd mount --bind "${share_path}" "${share_path}"
        run_cmd mount --bind -o remount,"${mount_opts}" "${share_path}" "${share_path}"
        log "noexec bind mount applied to ${share_path}"
    fi

    # Write a boot script that re-applies the mount after every array start.
    # We use a separate script file so it can be removed cleanly without
    # editing /boot/config/go directly.
    local mount_script="${BOOT_SCRIPTS_DIR}/forensics-noexec-${SHARE_NAME}.sh"

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would write mount script to ${mount_script}\033[0m"
    else
        mkdir --parents "${BOOT_SCRIPTS_DIR}"
        cat > "${mount_script}" <<MOUNTSCRIPT
#!/usr/bin/env bash
# forensics-noexec-${SHARE_NAME}.sh
# Re-applies noexec bind mount for the ${SHARE_NAME} share on each boot.
# Generated by forensics-share.sh — do not edit manually.
# To remove: delete this file and remove the line in /boot/config/go.

SHARE_PATH="/mnt/user/${SHARE_NAME}"
MOUNT_OPTS="${mount_opts}"

# Wait for the array to be started (the share path may not exist yet at boot)
retries=0
while [[ ! -d "\${SHARE_PATH}" ]] && [[ \${retries} -lt 30 ]]; do
    sleep 2
    ((retries++))
done

if [[ ! -d "\${SHARE_PATH}" ]]; then
    echo "[forensics-noexec] ERROR: \${SHARE_PATH} not available after 60s — array may not be started" >&2
    exit 1
fi

if mount | grep -q "\${SHARE_PATH}.*noexec"; then
    echo "[forensics-noexec] \${SHARE_PATH} already mounted noexec — skipping"
    exit 0
fi

mount --bind "\${SHARE_PATH}" "\${SHARE_PATH}" && \
mount --bind -o remount,\${MOUNT_OPTS} "\${SHARE_PATH}" "\${SHARE_PATH}" && \
echo "[forensics-noexec] Applied noexec,nosuid,nodev to \${SHARE_PATH}" || \
echo "[forensics-noexec] ERROR: Failed to apply noexec mount to \${SHARE_PATH}" >&2
MOUNTSCRIPT
        chmod 700 "${mount_script}"
        log "Wrote boot mount script to ${mount_script}"
    fi

    # Hook into /boot/config/go
    # We delay the call slightly (background with sleep) to ensure the array
    # has started before the mount is attempted.
    patch_go_file \
        "secure_oss: forensics noexec mount (${SHARE_NAME})" \
        "( sleep 30 && bash ${mount_script} ) &"

    log "noexec mount will be re-applied automatically on every boot."

    # Verify the mount is active
    if [[ "${DRY_RUN}" != "1" ]]; then
        if mount | grep --quiet "${share_path}.*noexec"; then
            log "VERIFIED: ${share_path} is mounted with noexec"
        else
            warn "Mount verification failed — check: mount | grep ${share_path}"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Step 2: Samba share hardening
#
# Unraid generates /etc/samba/smb.conf from its templates on each Samba
# start. We write our share-specific settings to /boot/config/smb-extra.conf
# (which Unraid includes at the end of the global section) and add a go hook
# that patches the share's section in smb.conf after Samba starts.
# ---------------------------------------------------------------------------

harden_samba() {
    banner "Samba share hardening"

    local smb_extra="/boot/config/smb-extra.conf"
    local patch_script="${BOOT_SCRIPTS_DIR}/forensics-samba-${SHARE_NAME}.sh"
    local begin_marker="### BEGIN secure_oss forensics ${SHARE_NAME} ###"
    local end_marker="### END secure_oss forensics ${SHARE_NAME} ###"

    # --- smb-extra.conf: global Samba hardening ---
    # These apply to ALL shares, not just the forensics one, but they are
    # correct security defaults that should always be set anyway.
    local global_block="### BEGIN secure_oss global Samba hardening ###
[global]
# Never follow symlinks within shares. Without this, a symlink named
# 'passwd' pointing to /etc/passwd would be readable by any Samba client.
follow symlinks = no

# Never follow symlinks that point outside the share root. This is the
# stronger form of the above — belt and suspenders.
wide links = no

# Disable NTLM authentication (legacy, susceptible to relay attacks).
# Clients must use NTLMv2 or Kerberos.
ntlm auth = no

# Don't reveal the server's OS version in protocol negotiation responses.
# Reduces attacker reconnaissance value.
server min protocol = SMB2
### END secure_oss global Samba hardening ###"

    if ! grep --quiet "BEGIN secure_oss global Samba hardening" "${smb_extra}" 2>/dev/null; then
        if [[ "${DRY_RUN}" == "1" ]]; then
            echo -e "\033[0;36m[DRY RUN] Would write to ${smb_extra}\033[0m"
            echo "${global_block}"
        else
            printf '\n%s\n' "${global_block}" >> "${smb_extra}"
            log "Appended global Samba hardening to ${smb_extra}"
        fi
    else
        log "Global Samba hardening already in ${smb_extra} — skipping"
    fi

    # --- Per-share patch script ---
    # After each Samba restart, Unraid regenerates smb.conf. We patch the
    # generated config to add our per-share options immediately after the
    # share section header.
    local ro_setting=""
    [[ "${READ_ONLY}" == "1" ]] && ro_setting=$'\n    read only = yes'

    if [[ "${DRY_RUN}" == "1" ]]; then
        echo -e "\033[0;36m[DRY RUN] Would write Samba patch script to ${patch_script}\033[0m"
    else
        mkdir --parents "${BOOT_SCRIPTS_DIR}"
        cat > "${patch_script}" <<PATCHSCRIPT
#!/usr/bin/env bash
# forensics-samba-${SHARE_NAME}.sh
# Patches the [${SHARE_NAME}] Samba share section in /etc/samba/smb.conf
# to add security hardening options after each Samba start.
# Generated by forensics-share.sh — do not edit manually.

SMB_CONF="/etc/samba/smb.conf"
SHARE="${SHARE_NAME}"
BEGIN="${begin_marker}"
END="${end_marker}"

if [[ ! -f "\${SMB_CONF}" ]]; then
    echo "[forensics-samba] smb.conf not found — Samba may not be running" >&2
    exit 0
fi

# Remove any previous injection
python3 - "\${SMB_CONF}" "\${BEGIN}" "\${END}" <<'PYEOF'
import sys, os
path, bm, em = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    lines = f.readlines()
out, inside = [], False
for l in lines:
    if bm in l: inside = True
    if not inside: out.append(l)
    if em in l: inside = False
with open(path, 'w') as f:
    f.writelines(out)
PYEOF

# Inject our hardened options into the [SHARE] section
python3 - "\${SMB_CONF}" "\${SHARE}" "\${BEGIN}" "\${END}" <<PYEOF2
import sys, re

path     = sys.argv[1]
share    = sys.argv[2]
begin_m  = sys.argv[3]
end_m    = sys.argv[4]

injection = (
    f"    # {begin_m}\\n"
    f"    follow symlinks = no\\n"
    f"    wide links = no\\n"
    f"    delete readonly = no\\n"${ro_setting:+$'\n    '"    read only = yes\\n"}
    f"    # {end_m}\\n"
)

with open(path) as f:
    content = f.read()

# Insert our block right after the [share_name] header line
pattern = rf'(\\[{re.escape(share)}\\][^\\n]*\\n)'
replacement = rf'\\1{injection}'
new_content = re.sub(pattern, replacement, content)

if new_content == content:
    print(f"[forensics-samba] WARNING: [{share}] section not found in {path}")
else:
    with open(path, 'w') as f:
        f.write(new_content)
    print(f"[forensics-samba] Patched [{share}] in {path}")
PYEOF2
PATCHSCRIPT
        chmod 700 "${patch_script}"
        log "Wrote Samba patch script to ${patch_script}"
    fi

    # Apply immediately to the live smb.conf and restart Samba
    if [[ "${DRY_RUN}" != "1" ]]; then
        bash "${patch_script}"
        # Reload Samba to pick up smb-extra.conf and patched config
        samba reload-config 2>/dev/null || true
    fi

    # Hook into go: run after Samba starts (which happens after array start)
    patch_go_file \
        "secure_oss: forensics Samba hardening (${SHARE_NAME})" \
        "( sleep 45 && bash ${patch_script} ) &"

    log "Samba hardening applied for share [${SHARE_NAME}]"
    log "  follow symlinks = no"
    log "  wide links = no"
    [[ "${READ_ONLY}" == "1" ]] && log "  read only = yes"
}

# ---------------------------------------------------------------------------
# Step 3: Docker container audit
#
# Scans all running (and stopped) containers for volume mounts that include
# the forensics share path. Does NOT make changes — reports only.
# You must decide whether to update those containers.
# ---------------------------------------------------------------------------

audit_docker_mounts() {
    banner "Docker container audit"

    local share_path="/mnt/user/${SHARE_NAME}"

    if ! command -v docker &>/dev/null; then
        log "Docker not found — skipping container audit."
        return 0
    fi

    log "Scanning all containers for mounts containing: ${share_path}"

    local containers_with_access=()
    local all_containers
    all_containers="$(docker ps -aq 2>/dev/null || true)"

    if [[ -z "${all_containers}" ]]; then
        log "No Docker containers found."
        return 0
    fi

    while IFS= read -r container_id; do
        [[ -z "${container_id}" ]] && continue

        local container_name mounts
        container_name="$(docker inspect --format '{{.Name}}' "${container_id}" 2>/dev/null | sed 's|^/||')"
        mounts="$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "${container_id}" 2>/dev/null || true)"

        for mount_src in ${mounts}; do
            if [[ "${mount_src}" == "${share_path}"* ]]; then
                containers_with_access+=("${container_name} (${container_id}) → ${mount_src}")
            fi
        done
    done <<< "${all_containers}"

    if [[ "${#containers_with_access[@]}" -eq 0 ]]; then
        log "No containers have access to ${share_path} — good."
        return 0
    fi

    echo ""
    warn "========================================================"
    warn "  DOCKER ACCESS RISK DETECTED"
    warn "  The following containers have mounts under ${share_path}:"
    warn "  These containers can READ files from your forensics"
    warn "  share. If a container process has a parser vulnerability"
    warn "  (e.g. an image viewer, media server, or file indexer),"
    warn "  malicious content in the share could exploit it."
    warn ""
    for entry in "${containers_with_access[@]}"; do
        warn "  CONTAINER: ${entry}"
    done
    warn ""
    warn "  ACTION REQUIRED:"
    warn "  Review each container above and remove the mount to"
    warn "  the forensics share unless it is intentional and safe."
    warn "  Update mounts in the Unraid Docker UI or docker-compose."
    warn "========================================================"
    echo ""
}

# ---------------------------------------------------------------------------
# Step 4: Media server exclusion markers
# ---------------------------------------------------------------------------

create_exclusion_markers() {
    banner "Media server exclusion markers"

    local share_path="/mnt/user/${SHARE_NAME}"

    # Plex Media Server: .plexignore in the root of a library path tells Plex
    # to skip files matching the patterns. A '*' ignores everything.
    # Note: This only works if Plex is scanning this directory AS a library.
    # The real fix is to never add this share to a Plex library. This is a
    # belt-and-suspenders fallback.
    run_cmd "printf '*\n' > '${share_path}/.plexignore'"
    log "Created ${share_path}/.plexignore (ignores all files)"

    # Jellyfin / Emby: These respect a .ignore file at the directory level
    run_cmd "printf '**\n' > '${share_path}/.ignore'"
    log "Created ${share_path}/.ignore (ignores all files)"

    # Generic media server: .nomedia tells Android MTP and many media scanners
    # to skip this directory entirely
    run_cmd "touch '${share_path}/.nomedia'"
    log "Created ${share_path}/.nomedia"

    # Sonarr/Radarr/Lidarr: These will still scan if pointed at this dir.
    # Cannot be blocked via file markers — must be configured to exclude
    # the path in the app itself.

    warn "Media server exclusion markers created."
    warn "IMPORTANT: Also verify that no media server application (Plex, Jellyfin,"
    warn "Emby, etc.) has this share configured as a library path. File markers"
    warn "are a fallback — the correct fix is to exclude the path in the app UI."
}

# ---------------------------------------------------------------------------
# Step 5: Filesystem permissions
# ---------------------------------------------------------------------------

set_permissions() {
    banner "Filesystem permissions"

    local share_path="/mnt/user/${SHARE_NAME}"

    log "Setting ownership root:root, mode 750 on ${share_path}"
    run_cmd chown root:root "${share_path}"
    run_cmd chmod 750 "${share_path}"

    # Remove world-readable bit from all existing content recursively.
    # This prevents the 'nobody' user (Samba guest, some containers) from
    # listing or reading files in the share without explicit permission.
    log "Removing world-readable/executable bits from existing content..."
    if [[ "${DRY_RUN}" == "1" ]]; then
        echo "[DRY RUN] Would run: find ${share_path} -mindepth 1 | xargs chmod o-rwx"
    else
        find "${share_path}" -mindepth 1 -exec chmod o-rwx {} + 2>/dev/null || true
        log "World bits removed from existing content."
    fi

    log "Permissions set. New files added to the share will inherit the directory's ACL."
    warn "If you access this share via Samba as a non-root user, ensure that user"
    warn "is in a group with read access (e.g. add to group: usermod -aG root <user>)."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    local share_path="/mnt/user/${SHARE_NAME}"

    echo ""
    echo -e "\033[1m=== Forensics Share Hardening Summary ===\033[0m"
    echo ""
    echo "  Share     : ${SHARE_NAME}"
    echo "  Path      : ${share_path}"
    echo "  Read-only : $([ "${READ_ONLY}" == "1" ] && echo "yes" || echo "no")"
    echo ""
    echo "Verification:"
    echo "  noexec  : mount | grep ${share_path}"
    echo "           (should contain: noexec,nosuid,nodev)"
    echo "  test    : cp /bin/ls ${share_path}/test_ls_tmp && ${share_path}/test_ls_tmp"
    echo "           (should fail: Permission denied)"
    echo "           rm -f ${share_path}/test_ls_tmp"
    echo "  Samba   : grep -A10 '\\[${SHARE_NAME}\\]' /etc/samba/smb.conf"
    echo "  Docker  : docker inspect <container> | grep -A5 Mounts"
    echo ""
    echo "Boot persistence:"
    echo "  Mount script  : ${BOOT_SCRIPTS_DIR}/forensics-noexec-${SHARE_NAME}.sh"
    echo "  Samba script  : ${BOOT_SCRIPTS_DIR}/forensics-samba-${SHARE_NAME}.sh"
    echo "  go hooks      : grep 'forensics' ${GO_FILE}"
    echo ""
    echo "To undo all changes:"
    echo "  umount ${share_path}"
    echo "  rm ${BOOT_SCRIPTS_DIR}/forensics-noexec-${SHARE_NAME}.sh"
    echo "  rm ${BOOT_SCRIPTS_DIR}/forensics-samba-${SHARE_NAME}.sh"
    echo "  Remove 'secure_oss: forensics' lines from ${GO_FILE}"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

parse_args "$@"

[[ "${EUID}" -ne 0 ]] && die "Must be run as root."
[[ ! -f "${GO_FILE}" ]] && die "/boot/config/go not found — is this Unraid?"

log "=== secure_oss forensics-share.sh ==="
log "Share: ${SHARE_NAME}  read-only: ${READ_ONLY}"

apply_noexec_mount
harden_samba
audit_docker_mounts
create_exclusion_markers
set_permissions
print_summary
