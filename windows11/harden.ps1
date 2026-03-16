#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Harden Windows 11 — telemetry, MDM block, remote access, firewall, network, BitLocker.

.DESCRIPTION
    Platform  : Windows 11 (Home / Pro / Enterprise)
    Purpose   : Applies a practical hardening baseline targeting the threat model
                defined in CLAUDE.md: anti-MDM, anti-surveillance, no unauthorized
                remote access, firewall-first.
    Tested on : Windows 11 23H2, 24H2
    Requires  : Administrator, Windows 11
                run provision.ps1 first (bloatware removal)

    USABILITY GUARANTEE: Every section documents its usability impact.
    No section breaks the Windows shell, Update, Store, Hello, or printing.

.PARAMETER DryRun
    Show what would be done without making any changes.

.PARAMETER Skip
    Comma-separated list of sections to skip.
    Valid values: telemetry, privacy, mdm, remoteaccess, firewall,
                  network, services, tasks, onedrive, autoplay, bitlocker,
                  deliveryopt, uac, defender, amt, monitor

.EXAMPLE
    .\harden.ps1
    .\harden.ps1 -DryRun
    .\harden.ps1 -Skip 'bitlocker,remoteaccess'

.NOTES
    Verification commands are listed in the header of each section and in the
    summary printed at the end of the script.

    Applied markers are stored in: C:\ProgramData\secure_oss\applied\
    Log file: C:\ProgramData\secure_oss\secure_oss.log

    To re-apply a section after it has been marked as done:
        Remove-Item C:\ProgramData\secure_oss\applied\<section>
        .\harden.ps1 -Skip <all other sections>
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$DryRun,
    [string]$Skip = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'lib\Common.ps1')

$Script:DryRun       = $DryRun.IsPresent
$Script:HardenFailed = $false
$SkipList            = if ($Skip) { $Skip -split ',' | ForEach-Object { $_.Trim() } } else { @() }

New-Item -ItemType Directory -Path 'C:\ProgramData\secure_oss' -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $Script:MarkerDir -Force -ErrorAction SilentlyContinue | Out-Null

Write-Log "=== secure_oss Windows 11 harden.ps1 v$($Script:ScriptVersion) ==="

Assert-Administrator
Assert-Windows11

if ($Script:DryRun) { Write-Warn 'Dry-run mode enabled — no changes will be made.' }

# ---------------------------------------------------------------------------
# Section 1: Telemetry
#
# Disables Windows diagnostic data collection at the maximum level permitted
# for the edition. The effective level depends on the Windows edition:
#   - Security (0): Enterprise/Education only — sends only security-essential data
#   - Required (1): All editions — minimum data, no usage analytics
#
# USABILITY IMPACT: None. Windows Update, Microsoft Store, and all applications
# continue to function normally. Error reporting pop-ups are suppressed but
# Windows Defender and Windows Update are NOT affected.
#
# Verification:
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' AllowTelemetry
#   winmgmt — check DiagTrack service is disabled
# ---------------------------------------------------------------------------

function Set-TelemetryHardening {
    if (Test-SectionApplied 'telemetry') {
        Write-Log 'Telemetry already configured — skipping (delete C:\ProgramData\secure_oss\applied\telemetry to re-apply)'
        return
    }

    Write-Log 'Disabling Windows telemetry and diagnostic data collection...'

    # HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection
    # AllowTelemetry:
    #   0 = Security level (Enterprise/Education only; on Home/Pro behaves like 1)
    #   1 = Required (minimum diagnostics — all editions)
    # We set 0 so Enterprise deployments get the strictest level; Home/Pro silently
    # interpret this as 1 (Required), which is still a significant reduction.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        'AllowTelemetry' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        'MaxTelemetryAllowed' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        'DisableOneSettingsDownloads' 1   # Block downloads of new telemetry configs from Microsoft

    # Legacy path for the same setting
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' `
        'AllowTelemetry' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' `
        'MaxTelemetryAllowed' 0

    # Disable the Windows Customer Experience Improvement Program (CEIP)
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' `
        'CEIPEnable' 0

    # Disable Application Impact Telemetry
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' `
        'AITEnable' 0

    # Disable Application Telemetry collection
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' `
        'DisableUAR' 1   # Disable User Activity Recording (Steps Recorder / Problem Steps Recorder)

    # Disable Windows Error Reporting
    # WER sends crash data (including memory dumps with potentially sensitive content)
    # to Microsoft. Disabling it stops the "send this problem to Microsoft?" dialog.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' `
        'Disabled' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' `
        'Disabled' 1

    # Disable Inventory Collector (tracks installed apps, drivers, and devices)
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' `
        'DisableInventory' 1

    # Disable Advertising ID (used to profile users for targeted ads across apps)
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' `
        'DisabledByGroupPolicy' 1
    # Per-user setting (applies to current user)
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' `
        'Enabled' 0

    # Disable connected user experiences and telemetry service (DiagTrack)
    # This service is the primary telemetry data upload service.
    Disable-WindowsService 'DiagTrack'       'Connected User Experiences and Telemetry — primary data uploader'
    Disable-WindowsService 'dmwappushservice' 'WAP Push Message Routing — telemetry transport'

    Write-UsabilityNote 'Windows Update, Defender, and Store are unaffected. Error reporting dialogs suppressed.'

    Mark-SectionApplied 'telemetry'
}

# ---------------------------------------------------------------------------
# Section 2: Privacy
#
# Disables Activity History, Timeline, Cortana, location tracking, and the
# Feedback Hub submission mechanism. These features collect and transmit
# personal usage data to Microsoft.
#
# USABILITY IMPACT:
#   - Activity History: Windows Timeline (Alt+Tab history across devices) removed.
#     Local task switching is unaffected.
#   - Cortana: Voice assistant disabled. Windows Search (Start menu search,
#     file search) continues to work normally — only online/Cortana integration
#     is removed.
#   - Location: System-level location disabled. Per-app location can still be
#     re-enabled in Settings > Privacy > Location if needed.
#
# Verification:
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' EnableActivityFeed
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' AllowCortana
# ---------------------------------------------------------------------------

function Set-PrivacyHardening {
    if (Test-SectionApplied 'privacy') {
        Write-Log 'Privacy already configured — skipping'
        return
    }

    Write-Log 'Configuring privacy settings...'

    # --- Activity History and Timeline ---
    # Activity History tracks apps used, files opened, websites visited, and
    # syncs this to the cloud for use in Timeline (cross-device task continuation).
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        'EnableActivityFeed' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        'PublishUserActivities' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
        'UploadUserActivities' 0

    # --- Cortana ---
    # Disables Cortana integration in Windows Search. The search box in the
    # taskbar continues to work for local file/app searches.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        'AllowCortana' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        'DisableWebSearch' 1              # Stop Start menu from sending searches to Bing
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        'ConnectedSearchUseWeb' 0         # Do not use web results in Search
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' `
        'AllowSearchToUseLocation' 0      # Don't send location data with searches

    Write-UsabilityNote 'Cortana voice assistant disabled. Taskbar search still works for local files and apps.'

    # --- Location Services ---
    # Disables the system-wide location service. Applications requesting location
    # data (e.g. Maps, Weather) will not receive it.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' `
        'DisableLocation' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' `
        'DisableLocationScripting' 1

    Write-UsabilityNote 'Location services disabled system-wide. Re-enable in Settings > Privacy > Location if needed.'

    # --- Feedback Hub / Diagnostic data ---
    # Prevents Windows from periodically prompting for feedback and sending
    # Siuf (Satisfaction Indicator UI for Feedback) data.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
        'DoNotShowFeedbackNotifications' 1
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' `
        'NumberOfSIUFInPeriod' 0
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules' `
        'PeriodInNanoSeconds' 0

    # --- App diagnostics ---
    # Prevent apps from accessing diagnostic information about other apps.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' `
        'LetAppsGetDiagnosticInfo' 2     # 2 = Force Deny

    # --- Microphone and camera access (policy default) ---
    # The policy sets the default — individual apps can still be granted access
    # by the user in Settings > Privacy. This just ensures the default is off.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' `
        'LetAppsAccessMicrophone' 2      # Force Deny default (user can still grant per-app)
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' `
        'LetAppsAccessCamera' 2

    Write-UsabilityNote 'Microphone/camera default set to Deny. Individual apps can still be granted access in Settings > Privacy.'

    # --- Input personalization (typing/inking data sent to Microsoft) ---
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' `
        'RestrictImplicitInkCollection' 1
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\InputPersonalization' `
        'RestrictImplicitTextCollection' 1
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings' `
        'AcceptedPrivacyPolicy' 0

    Mark-SectionApplied 'privacy'
}

# ---------------------------------------------------------------------------
# Section 3: MDM Enrollment Block
#
# Prevents this device from being enrolled into a Mobile Device Management
# (MDM) system — Microsoft Intune, Azure Active Directory (AAD) device join,
# or any third-party MDM provider. This stops:
#   - Automatic enrollment via company/school account sign-in
#   - Remote policy push from an employer or IT department
#   - Device management via Azure AD Join
#
# USABILITY IMPACT: Microsoft personal accounts (MSA) and local accounts are
# unaffected. If you use a work/school Azure AD account and WANT MDM management,
# skip this section with -Skip mdm.
#
# Verification:
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' DisableRegistration
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin' BlockAADWorkplaceJoin
# ---------------------------------------------------------------------------

function Block-MDMEnrollment {
    if (Test-SectionApplied 'mdm') {
        Write-Log 'MDM enrollment block already configured — skipping'
        return
    }

    Write-Log 'Blocking MDM/Intune/AAD device enrollment...'

    # Block MDM auto-enrollment when signing in with a work/school account
    # HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' `
        'DisableRegistration' 1

    # Prevent Azure Active Directory device join (AAD Join)
    # This stops the device from being enrolled into AAD, which is the
    # prerequisite for Intune MDM management.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin' `
        'BlockAADWorkplaceJoin' 1

    # Block workplace registration (adds device to organization tenant)
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Policies\Passcode' `
        'DevicePasswordEnabled' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' `
        'AutoEnrollMDM' 0

    # Disable Windows Autopilot enrollment agent
    # Autopilot is used by OEMs and IT departments to automatically enroll
    # devices into AAD/Intune during first setup.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' `
        'DisableWindowsConsumerFeatures' 1   # Also suppresses sponsored apps

    Write-UsabilityNote 'Microsoft personal accounts (MSA) are unaffected. Only corporate AAD/MDM enrollment is blocked.'

    Mark-SectionApplied 'mdm'
}

# ---------------------------------------------------------------------------
# Section 4: Remote Access
#
# Disables Remote Desktop Protocol (RDP), Remote Assistance, and Windows
# Remote Management (WinRM). These are all inbound remote administration
# surfaces — unnecessary and dangerous on a personal workstation.
#
# USABILITY IMPACT:
#   - RDP: If you use RDP from another machine to connect TO this machine,
#     skip this section or re-enable after: Settings > System > Remote Desktop
#   - Remote Assistance: "Quick Assist" for helping someone remotely is disabled.
#     The Quick Assist app (a separate UWP app) is NOT affected.
#   - WinRM: PowerShell remoting and Windows Management Instrumentation (WMI)
#     over the network are disabled. Local PowerShell is fully unaffected.
#
# Verification:
#   (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
#   Get-Service WinRM | Select-Object Status, StartType
# ---------------------------------------------------------------------------

function Disable-RemoteAccess {
    if (Test-SectionApplied 'remoteaccess') {
        Write-Log 'Remote access already configured — skipping'
        return
    }

    Write-Log 'Disabling remote access surfaces (RDP, Remote Assistance, WinRM)...'

    # --- Remote Desktop (RDP) ---
    # fDenyTSConnections = 1 disables all inbound RDP connections.
    # The Windows Firewall RDP rule is also explicitly disabled below.
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
        'fDenyTSConnections' 1
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
        'fDenyTSConnections' 1

    # Disable the RDP firewall rules
    Invoke-SafeCommand -Description 'Disable RDP firewall rules' -Action {
        Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
    }

    Write-UsabilityNote 'RDP disabled. Re-enable: Settings > System > Remote Desktop > toggle on.'

    # --- Remote Assistance ---
    # Remote Assistance allows a trusted helper to view or control the desktop.
    # fAllowToGetHelp = 0 disables both sending and receiving assistance.
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
        'fAllowToGetHelp' 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
        'fAllowToGetHelp' 0

    # --- WinRM (Windows Remote Management) ---
    # WinRM is used for PowerShell remoting, Windows Admin Center, and some
    # management tools. It should be disabled on personal workstations.
    Invoke-SafeCommand -Description 'Disable WinRM service and disable PS remoting' -Action {
        # Disable PS remoting (removes listener and disables WinRM firewall rules)
        Disable-PSRemoting -Force -ErrorAction SilentlyContinue

        Stop-Service   WinRM -Force -ErrorAction SilentlyContinue
        Set-Service    WinRM -StartupType Disabled -ErrorAction SilentlyContinue
    }

    # --- Windows Management Instrumentation (inbound network access) ---
    # Block WMI over the network (firewall). Local WMI (used by many tools) is unaffected.
    Invoke-SafeCommand -Description 'Disable Windows Management Instrumentation inbound firewall rules' -Action {
        Disable-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' `
            -ErrorAction SilentlyContinue
    }

    Write-UsabilityNote 'WinRM disabled. Local PowerShell and local WMI are fully unaffected.'

    Mark-SectionApplied 'remoteaccess'
}

# ---------------------------------------------------------------------------
# Section 5: Firewall
#
# Configures Windows Defender Firewall to default-deny all inbound connections
# on all profiles (Domain, Private, Public). Outbound is unrestricted by default
# — adding outbound rules requires careful analysis and is left to the operator.
#
# Also removes or disables known unnecessary inbound rules that ship enabled
# by default (file sharing, network discovery when not needed).
#
# USABILITY IMPACT: Established/return traffic for outbound connections is always
# allowed (stateful firewall). This does NOT break browsing, Windows Update,
# app downloads, etc. Inbound-initiated connections (e.g. from another machine
# trying to reach this one) are blocked.
#
# Verification:
#   netsh advfirewall show allprofiles | findstr "Inbound"
#   Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction
# ---------------------------------------------------------------------------

function Configure-Firewall {
    if (Test-SectionApplied 'firewall') {
        Write-Log 'Firewall already configured — skipping'
        return
    }

    Write-Log 'Configuring Windows Defender Firewall (default-deny inbound)...'

    Invoke-SafeCommand -Description 'Set default inbound action to Block on all profiles' -Action {
        Set-NetFirewallProfile -Profile Domain,Private,Public `
            -DefaultInboundAction  Block `
            -DefaultOutboundAction Allow `
            -NotifyOnListen        True `
            -Enabled               True
    }

    Write-UsabilityNote 'Default-deny inbound is set. Outbound connections (browsing, updates, etc.) are unrestricted.'

    # --- Disable file and printer sharing inbound rules ---
    # These rules are enabled by default on the Private profile and allow other
    # machines on the local network to access shared folders. Disable unless
    # you intentionally share files on the local network.
    Invoke-SafeCommand -Description 'Disable File and Printer Sharing inbound rules' -Action {
        Disable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' `
            -ErrorAction SilentlyContinue
    }

    Write-UsabilityNote 'File/printer sharing inbound rules disabled. Re-enable in Windows Defender Firewall if you need LAN file sharing.'

    # --- Disable Network Discovery ---
    # Network Discovery allows Windows to find and be found by other computers.
    # On a hardened personal machine, this is unnecessary and leaks the device
    # name and network topology to other LAN participants.
    Invoke-SafeCommand -Description 'Disable Network Discovery inbound rules' -Action {
        Disable-NetFirewallRule -DisplayGroup 'Network Discovery' `
            -ErrorAction SilentlyContinue
    }

    # Disable mDNS inbound rule (LLMNR/mDNS multicast — handled in network section too)
    Invoke-SafeCommand -Description 'Disable mDNS inbound firewall rule' -Action {
        Disable-NetFirewallRule -DisplayName 'mDNS (UDP-In)' -ErrorAction SilentlyContinue
    }

    Write-UsabilityNote 'Network Discovery disabled. The machine will not appear in "Network" in File Explorer on other devices.'

    Mark-SectionApplied 'firewall'
}

# ---------------------------------------------------------------------------
# Section 6: Network Protocol Hardening
#
# SMBv1: A 30-year-old file sharing protocol with no modern security features.
#         Used by WannaCry/NotPetya ransomware for lateral movement. Windows 11
#         ships with it disabled, but this verifies and enforces the setting.
#
# LLMNR:  Link-Local Multicast Name Resolution. A broadcast name resolution
#         protocol that attackers can spoof to capture NTLMv2 hashes via
#         tools like Responder. No functional benefit over DNS on modern networks.
#
# NetBIOS over TCP/IP: Legacy Windows name resolution and session service.
#         Used by LLMNR/NBT-NS poisoning attacks. Disabling it on modern
#         Windows networks that use DNS has no practical usability impact.
#
# USABILITY IMPACT:
#   - SMBv1: Only affects connections to very old file servers (Windows XP/2003 era).
#   - LLMNR: May affect mDNS-based local network discovery. DNS is unaffected.
#   - NetBIOS: May affect older NAS devices that require NetBIOS. Modern Samba
#              and Windows shares work without NetBIOS.
#
# Verification:
#   Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast
# ---------------------------------------------------------------------------

function Harden-NetworkProtocols {
    if (Test-SectionApplied 'network') {
        Write-Log 'Network protocols already configured — skipping'
        return
    }

    Write-Log 'Hardening network protocols (SMBv1, LLMNR, NetBIOS)...'

    # --- SMBv1 ---
    # Disable via PowerShell cmdlets (preferred — authoritative)
    Invoke-SafeCommand -Description 'Disable SMBv1 client' -Action {
        Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    }
    Invoke-SafeCommand -Description 'Disable SMBv1 server' -Action {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    }

    # Also set via registry (belt-and-suspenders; applies at driver level)
    # HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters  SMB1 = 0
    Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
        'SMB1' 0

    Write-UsabilityNote 'SMBv1 disabled. Modern file shares (Windows Vista+, Samba 3+) are unaffected.'

    # --- Disable SMBv1 dependency services ---
    # mrxsmb10 is the SMBv1 redirector driver — disable it as well
    Disable-WindowsService 'mrxsmb10' 'SMBv1 network redirector driver'

    # --- LLMNR (Link-Local Multicast Name Resolution) ---
    # HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient  EnableMulticast = 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
        'EnableMulticast' 0

    Write-UsabilityNote 'LLMNR disabled. DNS name resolution is unaffected. May affect mDNS-based LAN discovery.'

    # --- NetBIOS over TCP/IP ---
    # Must be set per-adapter. Value 2 = Disabled (1 = Enable, 0 = Use DHCP default).
    # HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*
    Invoke-SafeCommand -Description 'Disable NetBIOS over TCP/IP on all adapters' -Action {
        $netbtPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        if (Test-Path $netbtPath) {
            Get-ChildItem -Path $netbtPath | ForEach-Object {
                Set-ItemProperty -Path $_.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord -Force
            }
        }
    }

    Write-UsabilityNote 'NetBIOS over TCP/IP disabled. Modern SMB shares and DNS are unaffected. Legacy NAS devices may need it re-enabled.'

    # --- WPAD (Web Proxy Auto-Discovery) ---
    # WPAD allows automatic proxy discovery via DHCP/DNS and can be abused to
    # redirect traffic through an attacker-controlled proxy.
    # Disabling it at the DNS level prevents auto-discovery.
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' `
        'DisableWpad' 1
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' `
        'AutoDetect' 0

    Write-UsabilityNote 'WPAD auto-proxy discovery disabled. Manually configured proxies are unaffected.'

    Mark-SectionApplied 'network'
}

# ---------------------------------------------------------------------------
# Section 7: Services
#
# Disables Windows services that represent attack surface or telemetry with
# no meaningful benefit on a hardened personal workstation.
#
# USABILITY IMPACT documented per service below.
# ---------------------------------------------------------------------------

function Disable-UnnecessaryServices {
    if (Test-SectionApplied 'services') {
        Write-Log 'Services already configured — skipping'
        return
    }

    Write-Log 'Disabling unnecessary/insecure services...'

    # RemoteRegistry: Allows remote modification of the registry over the network.
    # This is never needed on a personal workstation.
    # USABILITY: None.
    Disable-WindowsService 'RemoteRegistry' 'Allows remote registry modification over network'

    # Fax: Legacy fax service. Not needed on modern workstations.
    # USABILITY: None unless you use a fax modem.
    Disable-WindowsService 'Fax' 'Legacy fax service'

    # XboxGipSvc: Xbox accessories management. Disable if not using Xbox controllers.
    # Note: If -KeepXbox was not passed to provision.ps1, this is moot.
    # USABILITY: Disabling breaks Xbox controller setup on first connect, but
    # standard HID gamepad input still works for most games.
    # We leave this at its default rather than forcing disable.

    # PrintNotify: Print notification service — required for printing.
    # DO NOT disable. Left as comment for documentation purposes.
    # Disable-WindowsService 'PrintNotify' — SKIPPED: breaks printing

    # WSearch: Windows Search indexing. Disabling speeds up disk but breaks
    # fast Start menu search. Left at default.
    # Disable-WindowsService 'WSearch' — SKIPPED: too disruptive to usability

    # Spooler: Print spooler (PrintNightmare). Disabling breaks printing entirely.
    # Only disable if this machine is guaranteed to never print.
    # Disable-WindowsService 'Spooler' — SKIPPED: breaks printing

    # Connected Devices Platform: Enables cross-device experiences (phone link, etc.)
    # Disabling breaks Phone Link but has no other UX impact.
    Disable-WindowsService 'CDPSvc'     'Connected Devices Platform — cross-device syncing'
    Disable-WindowsService 'CDPUserSvc' 'Connected Devices Platform user service'

    # Device Association Service: Used for pairing devices. Disable CDPSvc first.
    # We leave this alone as it can affect Bluetooth and printer pairing.

    # Geolocation Service
    Disable-WindowsService 'lfsvc' 'Geolocation service — sends location data to apps/Microsoft'

    # Downloaded Maps Manager: Downloads and manages offline maps.
    Disable-WindowsService 'MapsBroker' 'Offline maps download manager — calls home to Bing Maps'

    # Microsoft Account Sign-in Assistant: Used for MSA-based sign-in.
    # USABILITY: Disabling this breaks Microsoft account sign-in. Leave at default.
    # Disable-WindowsService 'wlidsvc' — SKIPPED: breaks Microsoft account

    # Retail Demo Service: Used in store demo mode. Safe to disable.
    Disable-WindowsService 'RetailDemo' 'Windows Retail Demo mode service'

    Write-UsabilityNote 'Phone Link, offline maps, and geolocation services disabled. Printing, Bluetooth, and standard hardware are unaffected.'

    Mark-SectionApplied 'services'
}

# ---------------------------------------------------------------------------
# Section 8: Telemetry Scheduled Tasks
#
# Windows ships with dozens of scheduled tasks that collect and transmit
# diagnostic, compatibility, usage, and census data. These are disabled
# individually. Windows Update and Defender tasks are NOT touched.
#
# USABILITY IMPACT: None. These tasks run silently in the background.
# Disabling them does not affect any user-visible feature.
#
# Verification:
#   Get-ScheduledTask -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program\*'
# ---------------------------------------------------------------------------

function Disable-TelemetryTasks {
    if (Test-SectionApplied 'tasks') {
        Write-Log 'Scheduled tasks already configured — skipping'
        return
    }

    Write-Log 'Disabling telemetry and diagnostic scheduled tasks...'

    # Customer Experience Improvement Program (CEIP)
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Customer Experience Improvement Program\' 'Consolidator'
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Customer Experience Improvement Program\' 'KernelCeipTask'
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Customer Experience Improvement Program\' 'UsbCeip'

    # Application Experience — telemetry / compatibility data collection
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Application Experience\' 'Microsoft Compatibility Appraiser'
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Application Experience\' 'ProgramDataUpdater'
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Application Experience\' 'StartupAppTask'
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Application Experience\' 'MareBackup'

    # AutoChk Proxy — disk error telemetry uploader
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Autochk\' 'Proxy'

    # Disk diagnostic data collector
    Disable-ScheduledTask-Safe '\Microsoft\Windows\DiskDiagnostic\' 'Microsoft-Windows-DiskDiagnosticDataCollector'
    Disable-ScheduledTask-Safe '\Microsoft\Windows\DiskDiagnostic\' 'Microsoft-Windows-DiskDiagnosticResolver'

    # Feedback (SIUF — Satisfaction Indicator UI Feedback)
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Feedback\Siuf\' 'DmClient'
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Feedback\Siuf\' 'DmClientOnScenarioDownload'

    # Windows Error Reporting queue submission
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Windows Error Reporting\' 'QueueReporting'

    # Maps — downloads offline map updates from Bing
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Maps\' 'MapsUpdateTask'
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Maps\' 'MapsToastTask'

    # Census — device inventory data sent to Microsoft
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Device Information\' 'Device'
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Device Information\' 'Device User'

    # MUI language telemetry
    Disable-ScheduledTask-Safe '\Microsoft\Windows\MUI\' 'LPRemove'

    # Windows Media Player usage statistics
    Disable-ScheduledTask-Safe '\Microsoft\Windows\Windows Media Sharing\' 'UpdateLibrary'

    # Retail demo task
    Disable-ScheduledTask-Safe '\Microsoft\Windows\RetailDemo\' 'CleanupOfflineContent'

    Write-Log 'Telemetry scheduled tasks disabled.'
    Mark-SectionApplied 'tasks'
}

# ---------------------------------------------------------------------------
# Section 9: OneDrive — disable cloud sync via policy
#
# Regardless of whether OneDrive was removed in provision.ps1, we apply the
# group policy registry key that disables personal OneDrive file sync. This
# prevents OneDrive from automatically redirecting Desktop/Documents/Pictures
# to the cloud without explicit user opt-in.
#
# Note: This does NOT disable OneDrive for Business (SharePoint sync) which
# is a separate service. Enterprise OneDrive is unaffected.
#
# USABILITY IMPACT: Personal file sync to Microsoft's consumer cloud is
# disabled. The OneDrive app (if present) will prompt to sign in but will
# not sync. Files already synced remain locally.
#
# Verification:
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' DisableFileSyncNGSC
# ---------------------------------------------------------------------------

function Disable-OneDriveSync {
    if (Test-SectionApplied 'onedrive') {
        Write-Log 'OneDrive sync already configured — skipping'
        return
    }

    Write-Log 'Disabling OneDrive consumer cloud sync via policy...'

    # HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive
    # DisableFileSyncNGSC = 1 — Prevents OneDrive from syncing files
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' `
        'DisableFileSyncNGSC' 1

    # Prevent OneDrive from being used as the default save location
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' `
        'DisableLibrariesDefaultSaveToOneDrive' 1

    Write-UsabilityNote 'OneDrive consumer sync disabled. OneDrive for Business (SharePoint) is unaffected.'

    Mark-SectionApplied 'onedrive'
}

# ---------------------------------------------------------------------------
# Section 10: AutoPlay / AutoRun
#
# AutoPlay prompts users to choose an action when media is inserted.
# AutoRun automatically executes code from removable media (CDs, USB drives).
# AutoRun is the primary mechanism behind USB-based malware drops.
#
# Windows Vista+ disabled AutoRun for non-optical drives, but it can still
# be triggered by crafted USB devices. This section disables both.
#
# USABILITY IMPACT: When you insert a USB drive or disc, Windows will no longer
# automatically open it or ask what to do. You can still access it manually
# through File Explorer. AutoPlay can be re-enabled in Settings > Bluetooth
# & devices > AutoPlay.
#
# Verification:
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' NoAutoplayfornonVolume
#   Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' DisableAutoplay
# ---------------------------------------------------------------------------

function Disable-AutoPlayAutoRun {
    if (Test-SectionApplied 'autoplay') {
        Write-Log 'AutoPlay/AutoRun already configured — skipping'
        return
    }

    Write-Log 'Disabling AutoPlay and AutoRun...'

    # Disable AutoPlay for all media types (policy — all users)
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' `
        'NoAutoplayfornonVolume' 1      # Disable AutoPlay for non-volume devices (USB HID, etc.)

    # Disable AutoPlay globally via policy
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        'NoDriveTypeAutoRun' 255        # 255 = disable for all drive types
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        'NoDriveTypeAutoRun' 255

    # Disable AutoRun for all drives (the actual code execution mechanism)
    Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        'NoAutorun' 1
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        'NoAutorun' 1

    # Per-user AutoPlay disable (Settings level)
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' `
        'DisableAutoplay' 1

    Write-UsabilityNote 'AutoPlay prompts suppressed. USB drives and discs are accessible in File Explorer as normal.'

    Mark-SectionApplied 'autoplay'
}

# ---------------------------------------------------------------------------
# Section 11: BitLocker
#
# Enables BitLocker full-disk encryption on the system drive (C:) if a TPM
# is available and the drive is not already encrypted. BitLocker protects
# data at rest against physical access attacks (stolen laptop, etc.).
#
# BitLocker requirements:
#   - TPM 2.0 (present on all Windows 11-certified hardware)
#   - UEFI Secure Boot
#   - No pending OS encryption
#
# The recovery key is saved to C:\ProgramData\secure_oss\BitLockerRecoveryKey.txt
# and MUST be copied to a safe location (printed, stored in a password manager)
# before rebooting. The script prompts before proceeding.
#
# USABILITY IMPACT: Transparent after initial encryption. Boot time may
# increase by 1-2 seconds. Encryption of a full drive takes time to complete
# in the background (does not interrupt use). If the TPM or Secure Boot is
# misconfigured, Windows may prompt for the recovery key at boot.
#
# Verification:
#   manage-bde -status C:
#   Get-BitLockerVolume -MountPoint C: | Select-Object VolumeStatus, EncryptionMethod
# ---------------------------------------------------------------------------

function Enable-BitLockerEncryption {
    if (Test-SectionApplied 'bitlocker') {
        Write-Log 'BitLocker already configured — skipping'
        return
    }

    Write-Log 'Checking BitLocker eligibility...'

    # Check if already encrypted
    $blVolume = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
    if ($blVolume -and $blVolume.VolumeStatus -ne 'FullyDecrypted') {
        Write-Log "C: drive is already encrypted (status: $($blVolume.VolumeStatus)) — skipping"
        Mark-SectionApplied 'bitlocker'
        return
    }

    # Check for TPM
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if (-not $tpm) {
        Write-Warn 'Get-Tpm command not available — cannot check TPM status.'
        Write-Warn 'Enable BitLocker manually: Settings > Privacy & Security > Device Encryption'
        return
    }

    if (-not $tpm.TpmPresent) {
        Write-Warn 'No TPM detected. BitLocker without TPM requires a USB startup key.'
        Write-Warn 'Enable BitLocker manually: Settings > Privacy & Security > Device Encryption'
        return
    }

    if (-not $tpm.TpmReady) {
        Write-Warn "TPM is present but not ready (status: $($tpm.TpmEnabled), $($tpm.TpmActivated))."
        Write-Warn 'Check TPM status in Device Manager or BIOS. BitLocker not enabled.'
        return
    }

    Write-Log "TPM is present and ready. TpmEnabled=$($tpm.TpmEnabled) TpmActivated=$($tpm.TpmActivated)"

    if ($Script:DryRun) {
        Write-Host '[DRY RUN] Would: Enable BitLocker on C: with XtsAes256 + TPM protector' -ForegroundColor Cyan
        Write-Host '[DRY RUN] Would: Save recovery key to C:\ProgramData\secure_oss\BitLockerRecoveryKey.txt' -ForegroundColor Cyan
        return
    }

    # Save recovery key to a known location before encrypting
    $recoveryKeyPath = 'C:\ProgramData\secure_oss\BitLockerRecoveryKey.txt'
    Write-Warn '==========================================================='
    Write-Warn '  IMPORTANT: BitLocker recovery key will be saved to:'
    Write-Warn "    $recoveryKeyPath"
    Write-Warn '  Copy this key to a safe location (password manager, print)'
    Write-Warn '  BEFORE rebooting. Without it, you cannot recover data if'
    Write-Warn '  the TPM is cleared or Secure Boot state changes.'
    Write-Warn '==========================================================='

    try {
        # Add TPM protector
        Add-BitLockerKeyProtector -MountPoint 'C:' -TpmProtector -ErrorAction Stop | Out-Null

        # Add recovery password protector and capture the generated key
        $recoveryProtector = Add-BitLockerKeyProtector `
            -MountPoint 'C:' `
            -RecoveryPasswordProtector `
            -ErrorAction Stop

        # Save recovery key to file
        $recoveryPassword = (Get-BitLockerVolume -MountPoint 'C:').KeyProtector |
            Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
            Select-Object -First 1 -ExpandProperty RecoveryPassword

        if ($recoveryPassword) {
            "BitLocker Recovery Key for C: drive`nGenerated: $(Get-Date)`n`n$recoveryPassword" |
                Set-Content -Path $recoveryKeyPath -Encoding UTF8
            # Restrict file access to Administrators only
            $acl = Get-Acl $recoveryKeyPath
            $acl.SetAccessRuleProtection($true, $false)
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'Administrators', 'FullControl', 'Allow'
            )
            $acl.AddAccessRule($adminRule)
            Set-Acl -Path $recoveryKeyPath -AclObject $acl
            Write-Log "Recovery key saved to: $recoveryKeyPath"
        }

        # Enable BitLocker encryption (XTS-AES 256 — strongest available)
        Enable-BitLocker `
            -MountPoint           'C:' `
            -EncryptionMethod     XtsAes256 `
            -SkipHardwareTest `
            -ErrorAction          Stop | Out-Null

        Write-Log 'BitLocker encryption started on C:. Encryption runs in the background.'
        Write-Log "Recovery key: $recoveryKeyPath"
        Write-Log 'IMPORTANT: Copy the recovery key to a safe location now.'

    } catch {
        Write-Warn "BitLocker could not be enabled: $_"
        Write-Warn 'Try enabling manually: Settings > Privacy & Security > Device Encryption'
        return
    }

    Write-UsabilityNote 'BitLocker encrypts in the background — the system remains fully usable during encryption.'

    Mark-SectionApplied 'bitlocker'
}

# ---------------------------------------------------------------------------
# Section 12: Delivery Optimization
#
# Delivery Optimization is Windows Update's peer-to-peer component. By default
# it can upload Windows updates to other PCs on the internet, using your
# bandwidth to serve Microsoft's update distribution.
#
# Setting DODownloadMode = 0 restricts downloads to Microsoft's servers only
# (HTTP only, no P2P). Windows Update itself continues to work normally.
#
# USABILITY IMPACT: None. Updates still arrive at the same time from Microsoft.
# Only the peer-to-peer upload/download behavior is removed.
#
# Verification:
#   Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' DODownloadMode
# ---------------------------------------------------------------------------

function Disable-DeliveryOptimization {
    if (Test-SectionApplied 'deliveryopt') {
        Write-Log 'Delivery Optimization already configured — skipping'
        return
    }

    Write-Log 'Disabling Delivery Optimization P2P upload (restricting to Microsoft CDN only)...'

    # DODownloadMode:
    #   0 = HTTP only (Microsoft CDN only, no P2P)
    #   1 = LAN only
    #   2 = LAN + Internet P2P
    #   3 = LAN + Internet P2P + Group (enterprise)
    # We set 0 — updates come only from Microsoft, no data is shared with peers.
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' `
        'DODownloadMode' 0

    Write-UsabilityNote 'Windows Update still works normally. Only P2P redistribution of updates is disabled.'

    Mark-SectionApplied 'deliveryopt'
}

# ---------------------------------------------------------------------------
# Section 13: UAC (User Account Control)
#
# UAC is Windows' primary privilege escalation gate. It intercepts attempts
# to run processes with elevated (administrator) privileges and prompts the
# user to approve them. Without UAC, any program can silently obtain admin
# rights. With it properly configured, malware that runs as a standard user
# cannot elevate without a visible consent prompt.
#
# Settings applied:
#   EnableLUA = 1                    — UAC is on (master switch)
#   ConsentPromptBehaviorAdmin = 2   — Admins see a consent prompt on the
#                                      secure desktop before any elevation.
#                                      (Default is 5 = prompt only for
#                                      non-Windows binaries, which is weaker)
#   ConsentPromptBehaviorUser = 3    — Standard users must enter admin
#                                      credentials to elevate (not auto-deny)
#   PromptOnSecureDesktop = 1        — UAC prompt appears on a separate secure
#                                      desktop, preventing other processes from
#                                      clicking "Yes" on your behalf (UIPI bypass)
#   EnableVirtualization = 1         — File/registry virtualization for legacy apps
#   EnableInstallerDetection = 1     — Detect and prompt for installer programs
#   EnableSecureUIAPaths = 1         — Require elevation for UIPI-exempt paths
#
# USABILITY IMPACT: Admin-level actions (installing software, changing system
# settings) will always show a consent prompt, even if you are already logged
# in as an administrator. This is the expected Windows behavior and is not
# more intrusive than the default.
#
# Verification:
#   (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
#   (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').ConsentPromptBehaviorAdmin
# ---------------------------------------------------------------------------

function Enable-UACHardening {
    if (Test-SectionApplied 'uac') {
        Write-Log 'UAC already configured — skipping'
        return
    }

    Write-Log 'Configuring UAC (User Account Control)...'

    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    # Master switch — ensure UAC is on
    # EnableLUA = 1 enables the entire UAC framework. Setting it to 0 disables
    # all elevation prompts and allows any process to silently gain admin rights.
    Set-RegistryValue $uacPath 'EnableLUA' 1

    # Admin prompt behavior on secure desktop
    # 0 = Elevate without prompting (dangerous — never use)
    # 1 = Prompt for credentials on secure desktop
    # 2 = Prompt for consent on secure desktop (our setting — visible, explicit)
    # 3 = Prompt for credentials (non-secure desktop)
    # 4 = Prompt for consent (non-secure desktop)
    # 5 = Prompt for consent for non-Windows binaries only (default — too permissive)
    Set-RegistryValue $uacPath 'ConsentPromptBehaviorAdmin' 2

    # Standard user prompt behavior
    # 0 = Auto-deny elevation requests (too restrictive for personal use)
    # 1 = Prompt for credentials on secure desktop
    # 3 = Prompt for credentials (non-secure desktop)
    Set-RegistryValue $uacPath 'ConsentPromptBehaviorUser' 3

    # Use the secure desktop for elevation prompts.
    # The secure desktop is an isolated input session that other processes
    # cannot interact with, preventing malware from auto-clicking "Allow".
    Set-RegistryValue $uacPath 'PromptOnSecureDesktop' 1

    # Enable file and registry virtualization for legacy applications
    # that try to write to protected locations (Program Files, HKLM registry).
    # Redirects writes to per-user virtual stores instead of failing/prompting.
    Set-RegistryValue $uacPath 'EnableVirtualization' 1

    # Automatically detect and prompt when installer programs are launched.
    # Helps catch silent privilege escalation by package installers.
    Set-RegistryValue $uacPath 'EnableInstallerDetection' 1

    # Only elevate UIAccess applications from secure locations
    # (Program Files, Windows directory). Prevents placing UIAccess-marked
    # executables in user-writable locations to bypass UIPI.
    Set-RegistryValue $uacPath 'EnableSecureUIAPaths' 1

    Write-UsabilityNote 'UAC consent prompt will appear for all admin-level actions on the secure desktop. This is standard expected behavior.'

    Mark-SectionApplied 'uac'
}

# ---------------------------------------------------------------------------
# Section 14: Windows Defender
#
# Ensures all Windows Defender / Microsoft Defender Antivirus protection
# features are enabled and configured at their strongest settings, including:
#
#   Real-time protection     — Scans files as they are accessed/created
#   Cloud-delivered protection — Uses Microsoft's cloud to identify new threats
#   Behavior monitoring      — Watches for suspicious process behavior
#   Network protection       — Blocks access to known malicious IPs/domains
#   PUA protection           — Blocks potentially unwanted applications
#   USB/removable drive scan — Scans USB drives automatically on insertion
#   Attack Surface Reduction — Targeted rules blocking common attack techniques
#
# ATTACK SURFACE REDUCTION (ASR) rules: A set of behavioral rules that block
# specific exploitation techniques regardless of whether the threat has a
# known signature. Applied in two tiers:
#   Block mode  — For rules with minimal false-positive risk on personal machines
#   Audit mode  — For rules that may flag legitimate Office/macro workflows
#                 (review the event log and promote to Block if clean)
#
# ASR audit events: Event Viewer > Applications and Services Logs >
#   Microsoft > Windows > Windows Defender > Operational (Event ID 1121 = blocked,
#   1122 = audited)
#
# USABILITY IMPACT: Real-time scanning adds minimal latency on modern hardware.
# Cloud protection may briefly delay execution of brand-new executables while
# the cloud query completes. USB drives are scanned before content is accessible
# (short delay for large drives). Network protection requires a reboot to take effect.
#
# Verification:
#   Get-MpPreference | Select-Object DisableRealtimeMonitoring, MAPSReporting,
#       EnableNetworkProtection, PUAProtection, DisableRemovableDriveScanning
#   Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
# ---------------------------------------------------------------------------

function Enable-DefenderHardening {
    if (Test-SectionApplied 'defender') {
        Write-Log 'Windows Defender already configured — skipping'
        return
    }

    # Verify Defender is available (may be replaced by a third-party AV)
    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Warn 'Set-MpPreference not available — Windows Defender may be replaced by a third-party AV.'
        Write-Warn 'Ensure your AV is configured equivalently. Skipping Defender section.'
        return
    }

    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $mpStatus) {
        Write-Warn 'Cannot query Defender status (Get-MpComputerStatus failed). Skipping.'
        return
    }

    Write-Log 'Configuring Windows Defender / Microsoft Defender Antivirus...'

    # -----------------------------------------------------------------------
    # Core protection features
    # -----------------------------------------------------------------------

    Invoke-SafeCommand -Description 'Enable real-time protection' -Action {
        Set-MpPreference -DisableRealtimeMonitoring $false
    }

    Invoke-SafeCommand -Description 'Enable behavior monitoring' -Action {
        Set-MpPreference -DisableBehaviorMonitoring $false
    }

    Invoke-SafeCommand -Description 'Enable script scanning' -Action {
        Set-MpPreference -DisableScriptScanning $false
    }

    Invoke-SafeCommand -Description 'Enable archive scanning' -Action {
        Set-MpPreference -DisableArchiveScanning $false
    }

    Invoke-SafeCommand -Description 'Enable email scanning' -Action {
        Set-MpPreference -DisableEmailScanning $false
    }

    Invoke-SafeCommand -Description 'Enable scanning of downloaded files and attachments' -Action {
        Set-MpPreference -DisableIOAVProtection $false
    }

    # -----------------------------------------------------------------------
    # Cloud-delivered protection
    #
    # Cloud protection queries Microsoft's cloud backend when Defender
    # encounters a file it cannot classify locally. This provides near-
    # real-time protection against new threats, even before signature updates.
    #
    # MAPSReporting:
    #   0 = Disabled
    #   1 = Basic (send minimal data)
    #   2 = Advanced (send full telemetry including file samples — our setting)
    # CloudBlockLevel:
    #   0 = Default
    #   2 = High (block at higher confidence threshold — more aggressive)
    #   6 = Zero tolerance (block anything not explicitly known safe)
    # We use High (2) — good protection without false-positive risk of zero-tolerance.
    # -----------------------------------------------------------------------

    Invoke-SafeCommand -Description 'Enable cloud-delivered protection (Advanced MAPS)' -Action {
        Set-MpPreference -MAPSReporting Advanced
    }

    Invoke-SafeCommand -Description 'Set cloud block level to High' -Action {
        Set-MpPreference -CloudBlockLevel High
    }

    Invoke-SafeCommand -Description 'Set cloud block timeout to 50 seconds' -Action {
        # Allow up to 50 seconds for the cloud query before falling back to local verdict.
        # Default is 10 seconds. Longer timeout catches more threats at the cost of brief
        # execution delay for genuinely new/unknown files.
        Set-MpPreference -CloudExtendedTimeout 50
    }

    # -----------------------------------------------------------------------
    # Sample submission
    # SubmitSamplesConsent:
    #   0 = Always prompt
    #   1 = Send safe samples automatically (files without PII; our setting)
    #   2 = Never send
    #   3 = Send all samples automatically
    # Value 1 sends benign file samples (executables, scripts) automatically
    # but prompts for files that may contain personal data (Office docs, PDFs).
    # -----------------------------------------------------------------------

    Invoke-SafeCommand -Description 'Configure automatic safe sample submission' -Action {
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples
    }

    # -----------------------------------------------------------------------
    # Network protection
    #
    # Blocks outbound connections to known malicious IPs, domains, and URLs
    # at the network layer (via the WFP driver), regardless of which browser
    # or application initiates them.
    #
    # Requires a reboot to take effect.
    # Mode: Enabled (block) vs AuditMode (log only)
    # -----------------------------------------------------------------------

    Invoke-SafeCommand -Description 'Enable network protection (block malicious IPs/domains)' -Action {
        Set-MpPreference -EnableNetworkProtection Enabled
    }

    Write-UsabilityNote 'Network protection requires a reboot to take effect.'

    # -----------------------------------------------------------------------
    # Potentially Unwanted Application (PUA) protection
    #
    # Blocks software categorized as PUA: bundled installers, adware, toolbars,
    # crypto-miners, and other software that is not outright malicious but
    # behaves undesirably. Common in "free software" bundles.
    # PUAProtection: 0 = Off, 1 = Block, 2 = Audit
    # -----------------------------------------------------------------------

    Invoke-SafeCommand -Description 'Enable PUA (Potentially Unwanted Application) protection' -Action {
        Set-MpPreference -PUAProtection Enabled
    }

    # -----------------------------------------------------------------------
    # USB / Removable drive scanning
    #
    # Automatically scans USB drives and other removable media when they are
    # inserted. This catches malware that spreads via USB (e.g. LNK-based
    # droppers, autorun malware) before the user opens any files.
    #
    # DisableRemovableDriveScanning = $false means scanning IS enabled.
    # -----------------------------------------------------------------------

    Invoke-SafeCommand -Description 'Enable automatic scan of USB/removable drives on insertion' -Action {
        Set-MpPreference -DisableRemovableDriveScanning $false
    }

    # Also enforce via registry (Group Policy path — survives MpPreference resets)
    # HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan  DisableRemovableDriveScanning = 0
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' `
        'DisableRemovableDriveScanning' 0

    Write-UsabilityNote 'USB drives are scanned on insertion. Large drives may take a moment before content is accessible.'

    # -----------------------------------------------------------------------
    # Attack Surface Reduction (ASR) rules
    #
    # Actions:
    #   0 = Disabled
    #   1 = Block
    #   2 = Audit (log but allow — use to evaluate before promoting to Block)
    #
    # BLOCK tier — low false-positive risk on a personal machine:
    # -----------------------------------------------------------------------

    Write-Log 'Configuring Attack Surface Reduction (ASR) rules...'

    # Rule: Block executable content from email client and webmail
    # Prevents executables, scripts, and office files from being launched
    # directly from email. A primary delivery vector for malware.
    # GUID: BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550
    Invoke-SafeCommand -Description 'ASR [BLOCK]: Block executable content from email' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' `
                         -AttackSurfaceReductionRules_Actions 'Enabled'
    }

    # Rule: Block execution of potentially obfuscated scripts
    # Detects scripts that use encoding/obfuscation to hide their behavior,
    # a hallmark of fileless malware and PowerShell exploitation.
    # GUID: 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC
    Invoke-SafeCommand -Description 'ASR [BLOCK]: Block obfuscated script execution' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' `
                         -AttackSurfaceReductionRules_Actions 'Enabled'
    }

    # Rule: Block credential stealing from Windows LSASS
    # Prevents tools like Mimikatz from reading LSASS process memory to
    # extract plaintext passwords, hashes, and Kerberos tickets.
    # GUID: 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2
    Invoke-SafeCommand -Description 'ASR [BLOCK]: Block credential stealing from LSASS' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' `
                         -AttackSurfaceReductionRules_Actions 'Enabled'
    }

    # Rule: Block Win32 API calls from Office macros
    # Office macros that call Win32 APIs (e.g. CreateProcess, VirtualAlloc)
    # are a common technique for macro-based malware to execute shellcode.
    # GUID: 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B
    Invoke-SafeCommand -Description 'ASR [BLOCK]: Block Win32 API calls from Office macros' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' `
                         -AttackSurfaceReductionRules_Actions 'Enabled'
    }

    # Rule: Block JavaScript and VBScript from launching downloaded executable content
    # Prevents drive-by downloads that use JS/VBS to download and run payloads.
    # GUID: D3E037E1-3EB8-44C8-A917-57927947596D
    Invoke-SafeCommand -Description 'ASR [BLOCK]: Block JS/VBS from launching downloaded executables' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'D3E037E1-3EB8-44C8-A917-57927947596D' `
                         -AttackSurfaceReductionRules_Actions 'Enabled'
    }

    # Rule: Block untrusted and unsigned processes that run from USB
    # Prevents execution of unsigned executables directly from USB drives.
    # Complements the USB scan-on-insertion feature above.
    # GUID: B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4
    Invoke-SafeCommand -Description 'ASR [BLOCK]: Block unsigned/untrusted processes from USB' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' `
                         -AttackSurfaceReductionRules_Actions 'Enabled'
    }

    # Rule: Block persistence through WMI event subscription
    # WMI subscriptions are a fileless persistence mechanism used by
    # advanced malware (APT frameworks, Emotet, etc.) to survive reboots.
    # GUID: E6DB77E5-3DF2-4CF1-B95A-636979351E5B
    Invoke-SafeCommand -Description 'ASR [BLOCK]: Block WMI persistence via event subscription' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'E6DB77E5-3DF2-4CF1-B95A-636979351E5B' `
                         -AttackSurfaceReductionRules_Actions 'Enabled'
    }

    # Rule: Block process creation from PSExec and WMI commands
    # Prevents lateral movement tools (PSExec, WMI exec) from spawning processes.
    # GUID: D1E49AAC-8F56-4280-B9BA-993A6D77406C
    Invoke-SafeCommand -Description 'ASR [BLOCK]: Block process creation via PSExec/WMI' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'D1E49AAC-8F56-4280-B9BA-993A6D77406C' `
                         -AttackSurfaceReductionRules_Actions 'Enabled'
    }

    # -----------------------------------------------------------------------
    # AUDIT tier — may trigger on legitimate Office/macro workflows.
    # Review Event Viewer > Windows Defender > Operational (Event ID 1122)
    # and promote to Block if no false positives are observed.
    # -----------------------------------------------------------------------

    # Rule: Block Office applications from creating child processes
    # Word/Excel/PowerPoint creating cmd.exe or PowerShell is a classic
    # macro malware pattern. Can trigger on some legitimate add-ins.
    # GUID: D4F940AB-401B-4EFC-AADC-AD5F3C50688A
    Invoke-SafeCommand -Description 'ASR [AUDIT]: Block Office apps from creating child processes' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' `
                         -AttackSurfaceReductionRules_Actions 'AuditMode'
    }

    # Rule: Block Office applications from creating executable content
    # Prevents Office macros from writing .exe/.dll files to disk.
    # Can trigger on legitimate business add-ins that generate scripts.
    # GUID: 3B576869-A4EC-4529-8536-B80A7769E899
    Invoke-SafeCommand -Description 'ASR [AUDIT]: Block Office apps from creating executable content' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   '3B576869-A4EC-4529-8536-B80A7769E899' `
                         -AttackSurfaceReductionRules_Actions 'AuditMode'
    }

    # Rule: Block Office apps from injecting code into other processes
    # Prevents macro-based shellcode injection into browser/system processes.
    # GUID: 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84
    Invoke-SafeCommand -Description 'ASR [AUDIT]: Block Office apps from injecting into processes' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' `
                         -AttackSurfaceReductionRules_Actions 'AuditMode'
    }

    # Rule: Block Adobe Reader from creating child processes
    # PDF exploits that spawn cmd.exe are blocked. Can trigger on legitimate
    # PDF workflows that launch external apps.
    # GUID: 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C
    Invoke-SafeCommand -Description 'ASR [AUDIT]: Block Adobe Reader from creating child processes' -Action {
        Add-MpPreference -AttackSurfaceReductionRules_Ids   '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' `
                         -AttackSurfaceReductionRules_Actions 'AuditMode'
    }

    Write-Log 'Windows Defender hardening complete.'
    Write-Log 'ASR rules in Block mode: email exec, obfuscated scripts, LSASS, Win32 API from macros, JS/VBS download, USB untrusted, WMI persistence, PSExec'
    Write-Log 'ASR rules in Audit mode: Office child processes, Office exec content, Office injection, Adobe child processes'
    Write-Log 'Promote Audit rules to Block after reviewing Event Viewer > Windows Defender > Operational (Event ID 1122)'
    Write-UsabilityNote 'Reboot required for network protection to take effect. All other Defender settings apply immediately.'

    Mark-SectionApplied 'defender'
}

# ---------------------------------------------------------------------------
# Section 15: Intel ME/AMT hardening
#
# Intel Management Engine (ME) runs independently at Ring -3 regardless of
# what Windows does. AMT (Active Management Technology) provides out-of-band
# remote management (KVM, power, network) reachable even when Windows is off.
#
# ┌──────────────────────────────────────────────────────────────────────────┐
# │  HARD LIMIT — what Windows-level hardening CANNOT do:                   │
# │                                                                          │
# │  In shared-NIC mode, AMT intercepts TCP packets on its ports BEFORE     │
# │  Windows sees them. Windows Firewall rules DO NOT block AMT network     │
# │  access. The firewall is bypassed at the NIC hardware level.            │
# │                                                                          │
# │  Primary mitigation: disable AMT/ME in BIOS/MEBx, then apply           │
# │  Intel firmware updates listed at intel.com/security-center.            │
# └──────────────────────────────────────────────────────────────────────────┘
#
# What this section achieves:
#   1. Disables Intel LMS (Local Manageability Service) — the Windows
#      user-space bridge to the ME firmware. Also disables UNS and
#      IntelAMTAgent if present.
#   2. Adds Windows Firewall rules blocking AMT ports (defense-in-depth;
#      does not stop hardware-level AMT access but blocks OS-path access)
#   3. Checks whether AMT ports are visible in the Windows network stack
#   4. Updates the deployed monitor script to watch for LMS re-enablement
#
# USABILITY IMPACT: Intel LMS is only needed if you intentionally use
# Intel AMT for remote management. Disabling it has no impact on normal
# Windows operation.
#
# Verification:
#   Get-Service LMS -ErrorAction SilentlyContinue | Select Name,Status,StartType
#   Get-NetFirewallRule -DisplayName 'secure_oss*AMT*' | Select DisplayName,Enabled,Action
#   Get-EventLog -LogName Application -Source SecureOSS -Newest 10
# ---------------------------------------------------------------------------

function Protect-IntelAMT {
    if (Test-SectionApplied 'amt') {
        Write-Log 'AMT hardening already applied — skipping'
        return
    }

    # Check if Intel ME hardware is present
    $meDevice = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Management Engine|MEI|HECI' } |
        Select-Object -First 1

    if (-not $meDevice) {
        Write-Log 'No Intel Management Engine device detected — skipping AMT hardening'
        Mark-SectionApplied 'amt'
        return
    }

    Write-Log "Intel ME device detected: $($meDevice.Name)"
    Write-Log 'Applying AMT/ME hardening...'

    # -----------------------------------------------------------------------
    # 1. Disable Intel ME user-space services
    # -----------------------------------------------------------------------
    # LMS (Local Manageability Service): Windows-side bridge to ME firmware.
    # Disabling it prevents local user-space tools from communicating with AMT.
    # Does NOT disable the ME hardware or prevent network-level AMT access.
    Invoke-SafeCommand -Description 'Disable Intel LMS (Local Manageability Service)' -Action {
        Disable-WindowsService 'LMS' 'Intel Local Manageability Service — OS-side AMT bridge'
    }

    # UNS: User Notification Service for Intel ME — companion to LMS
    Invoke-SafeCommand -Description 'Disable Intel UNS (User Notification Service)' -Action {
        $svc = Get-Service 'UNS' -ErrorAction SilentlyContinue
        if ($svc) { Disable-WindowsService 'UNS' 'Intel User Notification Service (AMT companion to LMS)' }
    }

    # IntelAMTAgent: present on some OEM configurations
    Invoke-SafeCommand -Description 'Disable IntelAMTAgent if present' -Action {
        $svc = Get-Service 'IntelAMTAgent' -ErrorAction SilentlyContinue
        if ($svc) { Disable-WindowsService 'IntelAMTAgent' 'Intel AMT Agent service' }
    }

    # -----------------------------------------------------------------------
    # 2. Windows Firewall rules for AMT ports
    # NOTE: These block OS-path AMT access and are defense-in-depth only.
    # In shared-NIC mode, AMT traffic never reaches Windows Firewall.
    # -----------------------------------------------------------------------
    Invoke-SafeCommand -Description 'Add Windows Firewall rules blocking AMT ports (defense-in-depth)' -Action {
        $tcpPorts  = @(16992, 16993, 16994, 16995, 664)
        $udpPort   = 623
        foreach ($p in $tcpPorts) {
            $name = "secure_oss — Block AMT TCP $p inbound"
            if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $name `
                    -Direction Inbound -Protocol TCP -LocalPort $p `
                    -Action Block -Profile Any `
                    -Description 'Block Intel AMT management port (secure-oss). Note: does not block hardware-level AMT in shared-NIC mode.' | Out-Null
            }
        }
        $udpName = "secure_oss — Block AMT UDP $udpPort inbound"
        if (-not (Get-NetFirewallRule -DisplayName $udpName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $udpName `
                -Direction Inbound -Protocol UDP -LocalPort $udpPort `
                -Action Block -Profile Any | Out-Null
        }
        Write-Log 'AMT port firewall rules added: TCP 16992-16995, 664; UDP 623'
    }

    # -----------------------------------------------------------------------
    # 3. Check current AMT port state
    # -----------------------------------------------------------------------
    Invoke-SafeCommand -Description 'Check for AMT port listeners' -Action {
        $amtPorts = @(16992, 16993, 16994, 16995)
        $listeners = @($amtPorts | ForEach-Object {
            Get-NetTCPConnection -LocalPort $_ -ErrorAction SilentlyContinue
        })
        if ($listeners.Count -gt 0) {
            Write-Warn 'AMT management ports are listening in the Windows network stack!'
            Write-Warn 'AMT is provisioned and active. Disable in BIOS/MEBx immediately.'
            $listeners | ForEach-Object { Write-Warn "  Port $($_.LocalPort): state=$($_.State)" }
        } else {
            Write-Log 'AMT ports not visible in Windows network stack.'
            Write-Log 'Note: In shared-NIC mode AMT bypasses Windows entirely — port absence does NOT confirm AMT is off.'
        }

        # Check if LMS was recently running (indicator AMT has been used)
        $lmsRan = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Service Control Manager'
        } -MaxEvents 200 -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match '\bLMS\b' -and $_.Message -match 'running' } |
            Select-Object -First 1
        if ($lmsRan) {
            Write-Warn "Intel LMS service was running recently ($($lmsRan.TimeCreated)) — AMT has been used on this system."
        }
    }

    # -----------------------------------------------------------------------
    # 4. Update deployed monitor to watch for LMS/AMT re-enablement
    # -----------------------------------------------------------------------
    Invoke-SafeCommand -Description 'Update monitor: add LMS/AMT services to known-RMM list' -Action {
        $monScript = 'C:\ProgramData\secure_oss\scripts\Invoke-MDMMonitor.ps1'
        if (Test-Path $monScript) {
            $content = Get-Content $monScript -Raw -ErrorAction SilentlyContinue
            if ($content -and $content -notmatch "'LMS'") {
                # Append LMS/UNS/IntelAMTAgent to the $KnownRMMServices array
                $content = $content -replace "('RemoteRegistry'\s*\))", `
                    "'RemoteRegistry',`n    'LMS',            # Intel Local Manageability Service (AMT)`n    'UNS',            # Intel User Notification Service (AMT)`n    'IntelAMTAgent'   # Intel AMT Agent`n)"
                Set-Content -Path $monScript -Value $content -Encoding UTF8 -Force
                Write-Log 'Updated deployed monitor: LMS, UNS, IntelAMTAgent added to known-service scan'
            } else {
                Write-Log 'Monitor already includes LMS in known-service list — no update needed'
            }
        } else {
            Write-Log 'Monitor script not yet deployed (run monitor section first) — LMS check will be included when monitor is applied'
        }
    }

    # -----------------------------------------------------------------------
    # 5. Document required manual actions
    # -----------------------------------------------------------------------
    Write-Warn ''
    Write-Warn '┌──────────────────────────────────────────────────────────────┐'
    Write-Warn '│  INTEL AMT/ME — EFFECTIVE MITIGATIONS                       │'
    Write-Warn '├──────────────────────────────────────────────────────────────┤'
    Write-Warn '│  AMT intercepts packets BEFORE Windows sees them.           │'
    Write-Warn '│  Windows Firewall does NOT protect against AMT access.      │'
    Write-Warn '│                                                              │'
    Write-Warn '│  RECOMMENDED (most practical):                              │'
    Write-Warn '│  Block AMT ports on your GATEWAY/ROUTER — this works        │'
    Write-Warn '│  because the gateway is upstream of the NIC.               │'
    Write-Warn '│  Ports: TCP 16992-16995, 664  /  UDP 623                   │'
    Write-Warn '│  Caveat: does not stop attackers already on your LAN.      │'
    Write-Warn '│  Use VLAN isolation for full protection.                   │'
    Write-Warn '│                                                              │'
    Write-Warn '│  ALSO RECOMMENDED:                                          │'
    Write-Warn '│  1. Disable AMT in BIOS/MEBx if your board exposes it      │'
    Write-Warn '│     Reboot → Ctrl+P at POST → MEBx → ME Features Setup    │'
    Write-Warn '│  2. Apply Intel firmware updates (intel.com/security-center)│'
    Write-Warn '└──────────────────────────────────────────────────────────────┘'
    Write-Warn ''
    Write-UsabilityNote 'Intel LMS disabled. AMT firewall rules added. No impact on normal Windows use.'

    Mark-SectionApplied 'amt'
}

# ---------------------------------------------------------------------------
# Section 16: MDM/RMM intrusion monitoring
#
# Deploys a monitor script and three scheduled tasks that alert you when MDM
# enrollment or remote management tools appear on the system:
#
#   Task 1 — "MDM Check at Logon"
#     Trigger : every user logon
#     Runs as : logged-in user (interactive session)
#     Checks  : MDM enrollment registry, WinRM running, RDP re-enabled,
#               known RMM service names, known RMM process names
#     Alerts  : Windows toast notification + Windows Event Log
#
#   Task 2 — "New Service Alert"
#     Trigger : Windows Event ID 7045 (Service Control Manager — new service)
#     Runs as : SYSTEM
#     Checks  : whether the new service matches known RMM patterns
#     Alerts  : Windows Event Log (Application/SecureOSS) + alert file
#               (shown as toast on next logon)
#
#   Task 3 — "MDM Enrollment Alert"
#     Trigger : DeviceManagement-Enterprise-Diagnostics-Provider events
#               (enrollment attempt/completion: EventIDs 20219, 1, 2)
#     Runs as : SYSTEM
#     Alerts  : Windows Event Log + alert file (shown on next logon)
#
# Monitor script path : C:\ProgramData\secure_oss\scripts\Invoke-MDMMonitor.ps1
# Alert files         : C:\ProgramData\secure_oss\alerts\  (cleared at logon)
# Event Log source    : Application log, Source=SecureOSS, EventID=9001
#
# Known RMM services detected:
#   TeamViewer, AnyDesk, LogMeIn, ScreenConnect, Splashtop, Kaseya,
#   NinjaRMM, ConnectWise Automate, Datto RMM, BeyondTrust, Pulseway,
#   Atera, GoTo Resolve, Zoho Assist, RemotePC
#
# USABILITY IMPACT: None. Tasks run silently in the background. Alerts only
# appear when a threat indicator is actually detected.
#
# Verification:
#   Get-ScheduledTask -TaskPath '\secure_oss\*'
#   Test-Path 'C:\ProgramData\secure_oss\scripts\Invoke-MDMMonitor.ps1'
#   Get-EventLog -LogName Application -Source SecureOSS -Newest 10
# ---------------------------------------------------------------------------

function Set-MonitoringHardening {
    if (Test-SectionApplied 'monitor') {
        Write-Log 'MDM/RMM monitoring already configured — skipping'
        return
    }

    Write-Log 'Deploying MDM/RMM intrusion monitoring...'

    $scriptsDir    = 'C:\ProgramData\secure_oss\scripts'
    $alertDir      = 'C:\ProgramData\secure_oss\alerts'
    $monitorScript = 'C:\ProgramData\secure_oss\scripts\Invoke-MDMMonitor.ps1'

    # -----------------------------------------------------------------------
    # Create directories
    # -----------------------------------------------------------------------
    Invoke-SafeCommand -Description 'Create monitor directories' -Action {
        New-Item -ItemType Directory -Path $scriptsDir -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item -ItemType Directory -Path $alertDir   -Force -ErrorAction SilentlyContinue | Out-Null
    }

    # -----------------------------------------------------------------------
    # Write Invoke-MDMMonitor.ps1
    # -----------------------------------------------------------------------
    Invoke-SafeCommand -Description 'Write Invoke-MDMMonitor.ps1' -Action {
        $content = @'
# Invoke-MDMMonitor.ps1 — MDM/RMM intrusion detection monitor
# Deployed by harden.ps1 — do not edit manually.
#
# Parameters:
#   -Trigger  Logon         : runs as user at logon — check state + show toasts
#   -Trigger  NewService    : runs as SYSTEM on Event 7045 — write alert file
#   -Trigger  MDMEnrollment : runs as SYSTEM on MDM event — write alert file
param([string]$Trigger = 'Logon')

$AlertDir  = 'C:\ProgramData\secure_oss\alerts'
$LogSource = 'SecureOSS'
$LogName   = 'Application'

# These lists cover common commercial RMM tools but are not exhaustive —
# new agents and rebranded tools appear regularly. Extend them to match
# any additional tools relevant to your environment.
$KnownRMMServices = @(
    'TeamViewer', 'TeamViewer_Service', 'tv_w32', 'tv_x64',
    'AnyDesk', 'AnyDeskService',
    'LogMeIn', 'LMIGuardianSvc', 'LogMeInRemoteManagement',
    'ScreenConnect', 'ScreenConnectService',
    'SplashtopRemoteService', 'SRAService',
    'KaseyaAgent', 'AgentMon', 'ManagedApplication',
    'NinjaRMMAgent', 'NinjaRMM',
    'ConnectWiseAutomate', 'CWAClient', 'LabTechService',
    'DWAgent', 'CagService',
    'BeyondTrustPRA', 'bomgar-scc',
    'PulseWayService', 'PWMAgent',
    'AteraAgent', 'AteraAgentSvc',
    'GoToAssistService', 'g2ax_comm_customer',
    'ZohoAssist', 'zoho_assist_service',
    'RemotePC', 'RemotePCService',
    'SyncroAgent', 'SyncroAgentService',
    'RemoteRegistry'
)

$KnownRMMProcesses = @(
    'TeamViewer', 'tv_w32', 'tv_x64', 'TeamViewer_Desktop',
    'AnyDesk',
    'LogMeIn', 'LMIIgnition',
    'ScreenConnect.Client', 'ScreenConnect.ClientService',
    'Splashtop', 'SplashtopStreamer',
    'dwagent', 'dwservice',
    'kaseya', 'AgentMon',
    'ninjarmm', 'ninjaone',
    'connectwise', 'cwautomate',
    'bomgar', 'sdcservice',
    'pulseway',
    'atera',
    'remotepc',
    'zohoassist'
)

function Write-Alert {
    param([string]$Title, [string]$Message)
    if (-not (Test-Path $AlertDir)) {
        New-Item -ItemType Directory -Path $AlertDir -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safe = $Title -replace '[^A-Za-z0-9-]', '_'
    $file = Join-Path $AlertDir "${ts}-${safe}.txt"
    Set-Content -Path $file -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ${Title}`n${Message}" -ErrorAction SilentlyContinue
    try {
        Write-EventLog -LogName $LogName -Source $LogSource -EventId 9001 `
            -EntryType Warning -Message "${Title}`n`n${Message}" -ErrorAction SilentlyContinue
    } catch {}
}

function Show-Toast {
    param([string]$Title, [string]$Message)
    try {
        $null = [Windows.UI.Notifications.ToastNotificationManager,
                 Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument,
                 Windows.Data.Xml.Dom, ContentType = WindowsRuntime]
        $xml  = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
                    [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $nodes = $xml.GetElementsByTagName('text')
        $nodes.Item(0).AppendChild($xml.CreateTextNode($Title))   | Out-Null
        $nodes.Item(1).AppendChild($xml.CreateTextNode($Message))  | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        # Use PowerShell's registered AUMID — works without app store registration
        $aumid = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($aumid).Show($toast)
    } catch {}
}

function Read-PendingAlerts {
    $pending = Get-ChildItem -Path $AlertDir -Filter '*.txt' -ErrorAction SilentlyContinue |
                   Sort-Object CreationTime | Select-Object -Last 10
    foreach ($f in $pending) {
        $raw = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $raw) { continue }
        $parts = ($raw.Trim() -split "`n", 2)
        $t = $parts[0] -replace '^\[.*?\] ', ''
        $m = if ($parts.Count -gt 1) { $parts[1] } else { 'See Event Viewer > Application (Source: SecureOSS).' }
        Show-Toast -Title $t -Message $m
        Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
    }
}

function Test-MDMEnrolled {
    $path = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path $path)) { return $false }
    $enrolled = Get-ChildItem $path -ErrorAction SilentlyContinue | Where-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $p.UPN -or ($p.EnrollmentState -and $p.EnrollmentState -ne 0)
    }
    return ($null -ne $enrolled -and @($enrolled).Count -gt 0)
}

function Test-WinRMRunning {
    $svc = Get-Service 'WinRM' -ErrorAction SilentlyContinue
    return ($null -ne $svc -and $svc.Status -eq 'Running')
}

function Test-RDPEnabled {
    $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
             -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
    return ($null -ne $v -and $v.fDenyTSConnections -eq 0)
}

function Get-ActiveRMMServices {
    return @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Running' -and (
            $KnownRMMServices -contains $_.ServiceName -or
            $KnownRMMServices -contains $_.DisplayName
        )
    })
}

function Get-ActiveRMMProcesses {
    $found = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $KnownRMMProcesses) {
        Get-Process -Name "*${name}*" -ErrorAction SilentlyContinue |
            ForEach-Object { $found.Add($_.Name) }
    }
    return $found
}

switch ($Trigger) {
    'Logon' {
        $findings = [System.Collections.Generic.List[string]]::new()
        if (Test-MDMEnrolled) {
            $findings.Add('MDM enrollment active — device is enrolled in a management system. Check: HKLM:\SOFTWARE\Microsoft\Enrollments')
        }
        if (Test-WinRMRunning) {
            $findings.Add('WinRM (PowerShell Remoting) is running — remote management surface is open. Disable: Disable-PSRemoting -Force')
        }
        if (Test-RDPEnabled) {
            $findings.Add('Remote Desktop (RDP) is enabled. Verify this is intentional. Disable: Set-ItemProperty HKLM:\...\Terminal Server fDenyTSConnections 1')
        }
        foreach ($svc in (Get-ActiveRMMServices)) {
            $findings.Add("RMM service running: $($svc.DisplayName) [$($svc.ServiceName)] — investigate: Get-Service '$($svc.ServiceName)'")
        }
        foreach ($proc in (Get-ActiveRMMProcesses)) {
            $findings.Add("RMM process running: ${proc} — investigate: Get-Process '${proc}'")
        }
        foreach ($finding in $findings) {
            Write-Alert -Title 'MDM/RMM Activity Detected' -Message $finding
            Show-Toast  -Title 'Security Alert — secure-oss'  -Message $finding
        }
        # Display any backlogged alerts written by SYSTEM-context tasks
        Read-PendingAlerts
    }
    'NewService' {
        Write-Alert -Title 'New Service Installed' `
            -Message 'A new Windows service was installed. Check Event Viewer > Windows Logs > System (Event ID 7045) for the service name. Also run: Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" -MaxEvents 5 | Select-Object TimeCreated,Message'
        # Check if it is a known RMM service
        foreach ($svc in (Get-ActiveRMMServices)) {
            Write-Alert -Title 'RMM Service Installed' `
                -Message "A known remote management service is now running: $($svc.DisplayName) [$($svc.ServiceName)]"
        }
    }
    'MDMEnrollment' {
        Write-Alert -Title 'MDM Enrollment Event Detected' `
            -Message 'An MDM enrollment event was logged. This device may have been enrolled into a management system. Check: Get-ChildItem ''HKLM:\SOFTWARE\Microsoft\Enrollments'' | Get-ItemProperty | Select-Object UPN,EnrollmentState'
    }
}
'@
        Set-Content -Path $monitorScript -Value $content -Encoding UTF8 -Force
        Write-Log "Wrote monitor script: $monitorScript"
    }

    # -----------------------------------------------------------------------
    # Register custom Event Log source (needed before first Write-EventLog)
    # -----------------------------------------------------------------------
    Invoke-SafeCommand -Description 'Register SecureOSS event log source' -Action {
        if (-not [System.Diagnostics.EventLog]::SourceExists('SecureOSS')) {
            [System.Diagnostics.EventLog]::CreateEventSource('SecureOSS', 'Application')
            Write-Log "Event log source 'SecureOSS' registered in Application log"
        } else {
            Write-Log "Event log source 'SecureOSS' already registered"
        }
    }

    # -----------------------------------------------------------------------
    # Task 1: At logon — runs as the logged-in user, checks state + toasts
    # -----------------------------------------------------------------------
    Invoke-SafeCommand -Description 'Create scheduled task: MDM Check at Logon' -Action {
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$monitorScript`" -Trigger Logon"
        $trigger   = New-ScheduledTaskTrigger -AtLogOn
        # BUILTIN\Users runs the task as whoever is logging in, in their interactive session
        $principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Limited
        $settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
                         -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
        Register-ScheduledTask -TaskPath '\secure_oss\' -TaskName 'MDM Check at Logon' `
            -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
            -Description 'Check for MDM enrollment and RMM tools at every user logon (secure-oss)' `
            -Force | Out-Null
        Write-Log 'Scheduled task created: \secure_oss\MDM Check at Logon'
    }

    # -----------------------------------------------------------------------
    # Task 2: Event-triggered on new service install (System log / Event 7045)
    # Runs as SYSTEM — writes alert file shown as toast on next logon
    # -----------------------------------------------------------------------
    Invoke-SafeCommand -Description 'Create scheduled task: New Service Alert (Event 7045)' -Action {
        $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Alert when a new Windows service is installed — possible RMM/MDM agent (secure-oss)</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Service Control Manager'] and EventID=7045]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Hidden>false</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File &quot;C:\ProgramData\secure_oss\scripts\Invoke-MDMMonitor.ps1&quot; -Trigger NewService</Arguments>
    </Exec>
  </Actions>
</Task>
"@
        Register-ScheduledTask -TaskPath '\secure_oss\' -TaskName 'New Service Alert' `
            -Xml $taskXml -Force | Out-Null
        Write-Log 'Scheduled task created: \secure_oss\New Service Alert (trigger: Event 7045)'
    }

    # -----------------------------------------------------------------------
    # Task 3: Event-triggered on MDM enrollment events
    # DeviceManagement-Enterprise-Diagnostics-Provider: EventIDs 20219, 1, 2
    # -----------------------------------------------------------------------
    Invoke-SafeCommand -Description 'Create scheduled task: MDM Enrollment Alert' -Action {
        $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Alert on MDM enrollment events — device being managed remotely (secure-oss)</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational"&gt;&lt;Select Path="Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational"&gt;*[System[EventID=20219 or EventID=1 or EventID=2]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Hidden>false</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File &quot;C:\ProgramData\secure_oss\scripts\Invoke-MDMMonitor.ps1&quot; -Trigger MDMEnrollment</Arguments>
    </Exec>
  </Actions>
</Task>
"@
        Register-ScheduledTask -TaskPath '\secure_oss\' -TaskName 'MDM Enrollment Alert' `
            -Xml $taskXml -Force | Out-Null
        Write-Log 'Scheduled task created: \secure_oss\MDM Enrollment Alert (trigger: MDM enrollment events)'
    }

    Write-Log 'MDM/RMM monitoring deployed.'
    Write-Log '  At every logon: checks MDM state, WinRM, RDP, known RMM services/processes'
    Write-Log '  On new service install (Event 7045): immediate alert to Event Log'
    Write-Log '  On MDM enrollment event: immediate alert to Event Log'
    Write-Log '  View alerts: Event Viewer > Application log > Source: SecureOSS (EventID 9001)'
    Write-UsabilityNote 'Monitor tasks run silently. Alerts appear as toast notifications and in Event Viewer > Application (Source: SecureOSS).'

    Mark-SectionApplied 'monitor'
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

function Write-Summary {
    $sections = @(
        'telemetry', 'privacy', 'mdm', 'remoteaccess', 'firewall',
        'network', 'services', 'tasks', 'onedrive', 'autoplay',
        'bitlocker', 'deliveryopt', 'uac', 'defender', 'amt', 'monitor'
    )

    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host '  Hardening Summary' -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host ''

    foreach ($s in $sections) {
        if ($SkipList -contains $s) {
            Write-Host "  - $s (skipped)" -ForegroundColor Yellow
        } elseif (Test-SectionApplied $s) {
            Write-Host "  + $s" -ForegroundColor Green
        } else {
            Write-Host "  x $s (not applied or failed)" -ForegroundColor Red
        }
    }

    Write-Host ''
    Write-Host 'Post-hardening checklist:' -ForegroundColor White
    Write-Host '  [ ] Reboot to ensure all registry/policy changes take effect'
    Write-Host '  [ ] Verify firewall: Get-NetFirewallProfile | Select Name,DefaultInboundAction'
    Write-Host '  [ ] Verify SMBv1:    Get-SmbServerConfiguration | Select EnableSMB1Protocol'
    Write-Host '  [ ] Verify RDP off:  (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server).fDenyTSConnections'
    Write-Host '  [ ] Verify WinRM:    Get-Service WinRM | Select Status,StartType'
    Write-Host '  [ ] Verify BitLocker: manage-bde -status C:'
    Write-Host '  [ ] Verify UAC:      (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA'
    Write-Host '  [ ] Verify Defender: Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled,IoavProtectionEnabled'
    Write-Host '  [ ] Verify USB scan: (Get-MpPreference).DisableRemovableDriveScanning  (should be False)'
    Write-Host '  [ ] Review ASR audit events: Event Viewer > Windows Defender > Operational (Event ID 1122)'
    Write-Host '  [ ] Verify monitor tasks:    Get-ScheduledTask -TaskPath ''\secure_oss\*'' | Select TaskName,State'
    Write-Host '  [ ] View MDM/RMM alerts:     Get-EventLog -LogName Application -Source SecureOSS -Newest 20'
    if (Test-Path 'C:\ProgramData\secure_oss\BitLockerRecoveryKey.txt') {
        Write-Host ''
        Write-Host '  *** IMPORTANT: Copy your BitLocker recovery key ***' -ForegroundColor Yellow
        Write-Host '  Location: C:\ProgramData\secure_oss\BitLockerRecoveryKey.txt' -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host "Log file: $($Script:LogFile)" -ForegroundColor Gray
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Invoke-Section -Name 'telemetry'    -Action { Set-TelemetryHardening }       -SkipList $SkipList
Invoke-Section -Name 'privacy'      -Action { Set-PrivacyHardening }          -SkipList $SkipList
Invoke-Section -Name 'mdm'          -Action { Block-MDMEnrollment }           -SkipList $SkipList
Invoke-Section -Name 'remoteaccess' -Action { Disable-RemoteAccess }          -SkipList $SkipList
Invoke-Section -Name 'firewall'     -Action { Configure-Firewall }            -SkipList $SkipList
Invoke-Section -Name 'network'      -Action { Harden-NetworkProtocols }       -SkipList $SkipList
Invoke-Section -Name 'services'     -Action { Disable-UnnecessaryServices }   -SkipList $SkipList
Invoke-Section -Name 'tasks'        -Action { Disable-TelemetryTasks }        -SkipList $SkipList
Invoke-Section -Name 'onedrive'     -Action { Disable-OneDriveSync }          -SkipList $SkipList
Invoke-Section -Name 'autoplay'     -Action { Disable-AutoPlayAutoRun }       -SkipList $SkipList
Invoke-Section -Name 'bitlocker'    -Action { Enable-BitLockerEncryption }    -SkipList $SkipList
Invoke-Section -Name 'deliveryopt'  -Action { Disable-DeliveryOptimization }  -SkipList $SkipList
Invoke-Section -Name 'uac'          -Action { Enable-UACHardening }           -SkipList $SkipList
Invoke-Section -Name 'defender'     -Action { Enable-DefenderHardening }      -SkipList $SkipList
Invoke-Section -Name 'amt'          -Action { Protect-IntelAMT }               -SkipList $SkipList
Invoke-Section -Name 'monitor'      -Action { Set-MonitoringHardening }        -SkipList $SkipList

Write-Summary

if ($Script:HardenFailed) {
    Write-Warn 'One or more sections encountered errors. Review the output above.'
    exit 1
}

Write-Log '=== harden.ps1 complete ==='
Write-Log 'Reboot recommended to ensure all registry and policy changes take effect.'
