#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Provision a fresh Windows 11 installation — remove bloatware and configure winget.

.DESCRIPTION
    Platform  : Windows 11 (Home / Pro / Enterprise)
    Purpose   : Removes pre-installed Microsoft and OEM bloatware, disables
                sponsored/suggested content, and verifies winget is ready for
                optional tool installation. Safe to run on a fresh install.
    Tested on : Windows 11 23H2, 24H2
    Requires  : Administrator, Windows 11

.PARAMETER DryRun
    Show what would be done without making any changes.

.PARAMETER KeepXbox
    Do not remove Xbox-related apps (keep if you use Xbox Game Pass / streaming).

.PARAMETER KeepOneDrive
    Do not remove/disable OneDrive (keep if you actively use it for personal files).
    Note: harden.ps1 disables OneDrive cloud sync policy regardless of this flag
    unless --skip onedrive is also passed.

.PARAMETER KeepTeams
    Do not remove Microsoft Teams (the consumer Chat version pre-installed in some builds).

.EXAMPLE
    .\provision.ps1
    .\provision.ps1 -DryRun
    .\provision.ps1 -KeepXbox -KeepTeams

.NOTES
    After this script completes, run:
        .\harden.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$DryRun,
    [switch]$KeepXbox,
    [switch]$KeepOneDrive,
    [switch]$KeepTeams
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $ScriptDir 'lib\Common.ps1')

$Script:DryRun      = $DryRun.IsPresent
$Script:HardenFailed = $false

New-Item -ItemType Directory -Path 'C:\ProgramData\secure_oss' -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $Script:MarkerDir -Force -ErrorAction SilentlyContinue | Out-Null

Write-Log "=== secure_oss Windows 11 provision.ps1 v$($Script:ScriptVersion) ==="

Assert-Administrator
Assert-Windows11

if ($Script:DryRun) { Write-Warn 'Dry-run mode enabled — no changes will be made.' }

# ---------------------------------------------------------------------------
# Section: Remove bloatware apps
#
# These are pre-installed applications that ship with Windows 11 but serve
# no productivity purpose for most users and often contain advertising,
# telemetry, or are simply unnecessary on a hardened system.
#
# USABILITY IMPACT: None of the removed apps affect OS functionality.
# Apps can be reinstalled from the Microsoft Store if needed later.
#
# NOT removed (preserved for usability):
#   Microsoft.WindowsCalculator     — useful
#   Microsoft.WindowsNotepad        — useful
#   Microsoft.Paint                 — useful
#   Microsoft.Photos                — useful (though limited)
#   Microsoft.Windows.Photos        — same
#   Microsoft.WindowsTerminal       — useful for power users
#   Microsoft.WindowsCamera         — useful on laptops
#   Microsoft.ScreenSketch          — Snipping Tool, useful
#   Microsoft.WindowsAlarms         — low-risk, small
# ---------------------------------------------------------------------------

function Remove-Bloatware {
    Write-Log 'Identifying bloatware packages to remove...'

    # Core bloatware list
    $appsToRemove = [System.Collections.Generic.List[string]]@(
        # Advertising / sponsored
        'Microsoft.BingNews',           # MSN News widget — telemetry, sponsored content
        'Microsoft.BingWeather',        # Weather app — calls home to Bing
        'Microsoft.BingSearch',         # Bing search bar
        'Microsoft.BingFinance',
        'Microsoft.BingSports',
        'Microsoft.BingTravel',

        # Microsoft productivity apps (consumer subscription nags)
        'Microsoft.MicrosoftOfficeHub', # "Get Office" upsell app
        'Microsoft.Todos',              # Microsoft To Do — not everyone uses it
        'Microsoft.People',             # People / contacts app — rarely used as a standalone
        'Microsoft.WindowsFeedbackHub', # Sends feedback/telemetry to Microsoft
        'Microsoft.GetHelp',            # Automated support agent — calls home
        'Microsoft.Getstarted',         # Windows tips and suggestions nag

        # Entertainment / games
        'Microsoft.MicrosoftSolitaireCollection',  # Solitaire with ads
        'Microsoft.ZuneMusic',          # Groove Music (renamed Media Player in later builds)
        'Microsoft.ZuneVideo',          # Movies & TV
        'Clipchamp.Clipchamp',          # Video editor with cloud sync/upload

        # Communication
        'Microsoft.YourPhone',          # Phone Link — mirrors phone, syncs clipboard cross-device

        # Miscellaneous
        'Microsoft.WindowsMaps',        # Maps — calls home to Bing Maps
        'Microsoft.MixedReality.Portal', # Windows Mixed Reality portal
        'Microsoft.3DBuilder',          # Legacy 3D printing app
        'Microsoft.Print3D',            # 3D Print app
        'Microsoft.MSPaint',            # Paint 3D (NOT MS Paint — Paint 3D is the telemetry one)
        'LinkedInforWindows',           # LinkedIn app
        'Microsoft.PowerAutomateDesktop', # Power Automate — enterprise automation, rarely needed personally
        'MicrosoftCorporationII.MicrosoftFamily' # Family Safety — parental controls/surveillance app
    )

    # Xbox-related (preserved with -KeepXbox)
    if (-not $KeepXbox) {
        $xboxApps = @(
            'Microsoft.GamingApp',           # Xbox app (new)
            'Microsoft.Xbox.TCUI',           # Xbox UI library
            'Microsoft.XboxApp',             # Xbox app (old)
            'Microsoft.XboxGameOverlay',     # Xbox game overlay
            'Microsoft.XboxGamingOverlay',   # Xbox Game Bar overlay
            'Microsoft.XboxIdentityProvider',# Xbox identity/sign-in
            'Microsoft.XboxSpeechToTextOverlay'
        )
        $appsToRemove.AddRange($xboxApps)
    } else {
        Write-Warn 'Keeping Xbox apps (-KeepXbox)'
    }

    # Microsoft Teams consumer (not the enterprise client)
    if (-not $KeepTeams) {
        $appsToRemove.Add('MicrosoftTeams')   # Consumer Teams (chat, pre-pinned on 22H2)
        $appsToRemove.Add('MSTeams')          # New Teams app name on 24H2
    } else {
        Write-Warn 'Keeping Microsoft Teams (-KeepTeams)'
    }

    $removed = 0
    $notFound = 0

    foreach ($appName in $appsToRemove) {
        $packages = Get-AppxPackage -AllUsers -Name $appName -ErrorAction SilentlyContinue
        $provPkg  = Get-AppxProvisionedPackage -Online |
                    Where-Object { $_.DisplayName -eq $appName } -ErrorAction SilentlyContinue

        if (-not $packages -and -not $provPkg) {
            Write-Log "  $appName — not installed, skipping"
            $notFound++
            continue
        }

        if ($Script:DryRun) {
            Write-Host "[DRY RUN] Would remove: $appName" -ForegroundColor Cyan
            continue
        }

        Write-Log "  Removing: $appName"
        try {
            # Remove for all users
            if ($packages) {
                $packages | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            }
            # Remove provisioned package so it is not re-installed for new user accounts
            if ($provPkg) {
                $provPkg | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
            }
            $removed++
        } catch {
            Write-Warn "  Could not remove $appName : $_"
        }
    }

    Write-Log "Bloatware removal: $removed removed, $notFound not found."
}

# ---------------------------------------------------------------------------
# Section: Disable sponsored / suggested content in the shell
#
# Windows 11 shows sponsored apps in the Start menu, "suggested" apps in
# Settings, tips/tricks overlays, and other advertising surfaces.
# These registry settings suppress all of those without affecting functionality.
#
# USABILITY IMPACT: None. These are pure advertising/suggestion toggles.
# ---------------------------------------------------------------------------

function Disable-SuggestedContent {
    Write-Log 'Disabling sponsored/suggested content in shell and Start menu...'

    # HKCU settings — applied to the current user profile.
    # Note: These must be applied per-user. This script applies them to the
    # account running the script (typically the primary user on a personal machine).

    # Disable app suggestions in Start menu
    # HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'SystemPaneSuggestionsEnabled' 0
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'SubscribedContentEnabled' 0
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'SoftLandingEnabled' 0
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'RotatingLockScreenEnabled' 0
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'RotatingLockScreenOverlayEnabled' 0

    # Disable "Get even more out of Windows" suggestions
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'SubscribedContent-338388Enabled' 0   # Start menu suggestions
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'SubscribedContent-338389Enabled' 0   # Lock screen tips
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'SubscribedContent-353694Enabled' 0   # Settings suggestions
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'SubscribedContent-353696Enabled' 0   # Settings page tips
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'SubscribedContent-338393Enabled' 0   # Spotlight suggestions
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' `
        'SubscribedContent-310093Enabled' 0   # Windows tips

    # Disable "Recommended" section in Start menu (shows recently installed/used apps)
    # HKLM policy — affects all users
    Set-RegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' `
        'HideRecommendedSection' 1
    Write-UsabilityNote 'Start menu Recommended section hidden (policy key). The Start menu itself is unaffected.'

    # Disable File Explorer "Sync provider notifications" (sponsored OneDrive banners)
    Set-RegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
        'ShowSyncProviderNotifications' 0

    Write-Log 'Sponsored/suggested content disabled.'
}

# ---------------------------------------------------------------------------
# Section: Disable OneDrive (unless -KeepOneDrive)
#
# OneDrive syncs Desktop, Documents, and Pictures to Microsoft cloud by default
# on consumer Windows 11. This section silently uninstalls it. The policy-level
# disable is handled in harden.ps1 regardless of this flag.
#
# USABILITY IMPACT: Files already synced remain locally. The OneDrive icon
# disappears from the taskbar and File Explorer sidebar.
# OneDrive can be reinstalled from the Microsoft Store if needed.
# ---------------------------------------------------------------------------

function Remove-OneDrive {
    if ($KeepOneDrive) {
        Write-Warn 'Keeping OneDrive (-KeepOneDrive). Policy-level sync disable is applied in harden.ps1.'
        return
    }

    Write-Log 'Removing OneDrive...'

    # Stop OneDrive process first
    Invoke-SafeCommand -Description 'Stop OneDrive process' -Action {
        Stop-Process -Name 'OneDrive' -Force -ErrorAction SilentlyContinue
    }

    # Run the OneDrive uninstaller (ships with Windows)
    $oneDriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (-not (Test-Path $oneDriveSetup)) {
        $oneDriveSetup = "$env:SystemRoot\System32\OneDriveSetup.exe"
    }

    if (Test-Path $oneDriveSetup) {
        Invoke-SafeCommand -Description "Run OneDrive uninstaller: $oneDriveSetup /uninstall" -Action {
            Start-Process -FilePath $oneDriveSetup -ArgumentList '/uninstall' -Wait -NoNewWindow
        }
    } else {
        Write-Warn 'OneDriveSetup.exe not found — OneDrive may already be removed or using a non-standard path.'
    }

    # Remove leftover shell integration entries
    Invoke-SafeCommand -Description 'Remove OneDrive from File Explorer namespace' -Action {
        Remove-Item 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue
        Remove-Item 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue
    }

    Write-UsabilityNote 'OneDrive removed. Files remain in C:\Users\<user>\OneDrive\ if previously synced.'
    Write-Log 'OneDrive removed.'
}

# ---------------------------------------------------------------------------
# Section: Verify winget
#
# winget (Windows Package Manager) is the standard tool for installing
# applications on Windows 11. It ships pre-installed on 22H2+ but may need
# a manual installation on older builds or immediately after a fresh install
# before the first Store update runs.
# ---------------------------------------------------------------------------

function Test-Winget {
    Write-Log 'Checking winget availability...'

    if ($Script:DryRun) {
        Write-Host '[DRY RUN] Would verify winget is available' -ForegroundColor Cyan
        return
    }

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        $version = & winget --version 2>/dev/null
        Write-Log "winget is available: $version"
    } else {
        Write-Warn 'winget not found in PATH.'
        Write-Warn 'Install it from: https://aka.ms/getwinget or from the Microsoft Store.'
        Write-Warn 'winget is required for optional software installation steps.'
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Invoke-Section -Name 'bloatware'         -Action { Remove-Bloatware }          -SkipList @()
Invoke-Section -Name 'suggested-content' -Action { Disable-SuggestedContent }   -SkipList @()
Invoke-Section -Name 'onedrive-removal'  -Action { Remove-OneDrive }            -SkipList @()
Invoke-Section -Name 'winget-check'      -Action { Test-Winget }                -SkipList @()

Write-Log ''
Write-Log '=== provision.ps1 complete ==='
Write-Log ''
Write-Log "Next step: .\harden.ps1"
Write-Log '  Options: -DryRun  -Skip <sections>  -SshPort <port>'
Write-Log ''
