# lib/Common.ps1 — Shared utilities for secure_oss Windows 11 scripts
# Dot-sourced by provision.ps1 and harden.ps1; not executed directly.
#
# Platform : Windows 11 (Home / Pro / Enterprise)
# Purpose  : Logging, dry-run handling, idempotency markers, registry helpers

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

$Script:ScriptVersion = '0.1.0'
$Script:LogFile       = 'C:\ProgramData\secure_oss\secure_oss.log'
$Script:MarkerDir     = 'C:\ProgramData\secure_oss\applied'
# $Script:DryRun is set by the calling script from its -DryRun parameter

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Write-Log {
    param([string]$Message)
    $ts  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $msg = "[$ts] $Message"
    Write-Host $msg -ForegroundColor Green
    Add-Content -Path $Script:LogFile -Value $msg -ErrorAction SilentlyContinue
}

function Write-Warn {
    param([string]$Message)
    $ts  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $msg = "[$ts] WARNING: $Message"
    Write-Host $msg -ForegroundColor Yellow
    Add-Content -Path $Script:LogFile -Value $msg -ErrorAction SilentlyContinue
}

function Write-Fatal {
    param([string]$Message)
    $ts  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $msg = "[$ts] FATAL: $Message"
    Write-Host $msg -ForegroundColor Red
    Add-Content -Path $Script:LogFile -Value $msg -ErrorAction SilentlyContinue
    exit 1
}

function Write-Banner {
    param([string]$Title)
    $line = '=' * 60
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Dry-run wrapper
# ---------------------------------------------------------------------------

function Invoke-SafeCommand {
    <#
    .SYNOPSIS
        Executes a script block, or prints what it would do in dry-run mode.
    .PARAMETER Description
        Human-readable description shown in dry-run output.
    .PARAMETER Action
        Script block to execute when not in dry-run mode.
    #>
    param(
        [string]$Description,
        [scriptblock]$Action
    )
    if ($Script:DryRun) {
        Write-Host "[DRY RUN] Would: $Description" -ForegroundColor Cyan
    } else {
        Write-Log "Executing: $Description"
        & $Action
    }
}

# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

function Set-RegistryValue {
    <#
    .SYNOPSIS
        Creates or updates a registry value. Creates the key path if needed.
    .PARAMETER Path
        Registry path (e.g. HKLM:\SOFTWARE\Policies\...)
    .PARAMETER Name
        Value name
    .PARAMETER Value
        Value data
    .PARAMETER Type
        Registry value type: DWord (default), String, QWord, Binary, MultiString, ExpandString
    #>
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = 'DWord'
    )

    $desc = "Set registry [$Path] $Name = $Value ($Type)"

    if ($Script:DryRun) {
        Write-Host "[DRY RUN] Would: $desc" -ForegroundColor Cyan
        return
    }

    Write-Log $desc

    # Create the key path if it does not exist
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

function Remove-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    if (-not (Test-Path $Path)) { return }

    $desc = "Remove registry value [$Path] $Name"
    if ($Script:DryRun) {
        Write-Host "[DRY RUN] Would: $desc" -ForegroundColor Cyan
        return
    }
    Write-Log $desc
    Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------

function Disable-WindowsService {
    <#
    .SYNOPSIS
        Stops and disables a Windows service by name.
    .PARAMETER ServiceName
        The service short name (not display name).
    .PARAMETER Reason
        Human-readable reason for disabling (for log output).
    #>
    param(
        [string]$ServiceName,
        [string]$Reason = ''
    )

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log "  Service '$ServiceName' not found — skipping"
        return
    }

    $reasonStr = if ($Reason) { " ($Reason)" } else { '' }

    if ($svc.StartType -eq 'Disabled' -and $svc.Status -eq 'Stopped') {
        Write-Log "  Service '$ServiceName' already disabled and stopped — skipping"
        return
    }

    Invoke-SafeCommand -Description "Stop and disable service: $ServiceName$reasonStr" -Action {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Set-Service  -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Scheduled task helpers
# ---------------------------------------------------------------------------

function Disable-ScheduledTask-Safe {
    <#
    .SYNOPSIS
        Disables a scheduled task if it exists.
    .PARAMETER TaskPath
        Task folder path (e.g. \Microsoft\Windows\Customer Experience Improvement Program\)
    .PARAMETER TaskName
        Task name within the folder.
    #>
    param(
        [string]$TaskPath,
        [string]$TaskName
    )

    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Log "  Task '$TaskPath$TaskName' not found — skipping"
        return
    }

    if ($task.State -eq 'Disabled') {
        Write-Log "  Task '$TaskPath$TaskName' already disabled — skipping"
        return
    }

    Invoke-SafeCommand `
        -Description "Disable scheduled task: $TaskPath$TaskName" `
        -Action { Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName | Out-Null }
}

# ---------------------------------------------------------------------------
# Idempotency markers
# ---------------------------------------------------------------------------

function Test-SectionApplied {
    param([string]$Section)
    return (Test-Path (Join-Path $Script:MarkerDir $Section))
}

function Mark-SectionApplied {
    param([string]$Section)
    if ($Script:DryRun) { return }
    if (-not (Test-Path $Script:MarkerDir)) {
        New-Item -ItemType Directory -Path $Script:MarkerDir -Force | Out-Null
    }
    (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Set-Content (Join-Path $Script:MarkerDir $Section)
}

# ---------------------------------------------------------------------------
# Section runner
# ---------------------------------------------------------------------------

function Invoke-Section {
    <#
    .SYNOPSIS
        Runs a hardening section function, with skip support and error isolation.
    .PARAMETER Name
        Section name (used for skip-checking and idempotency markers).
    .PARAMETER Action
        Script block containing the section logic.
    .PARAMETER SkipList
        Array of section names to skip (passed from the caller's -Skip parameter).
    #>
    param(
        [string]$Name,
        [scriptblock]$Action,
        [string[]]$SkipList = @()
    )

    if ($SkipList -contains $Name) {
        Write-Warn "Skipping section: $Name (-Skip requested)"
        return
    }

    Write-Banner $Name

    try {
        & $Action
        Write-Log "Section '$Name' completed successfully."
    } catch {
        Write-Warn "Section '$Name' encountered an error: $_"
        Write-Warn "Continuing with remaining sections."
        $Script:HardenFailed = $true
    }
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

function Assert-Administrator {
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Fatal 'This script must be run as Administrator. Right-click PowerShell -> Run as Administrator.'
    }
}

function Assert-Windows11 {
    $osVersion = [System.Environment]::OSVersion.Version
    $productName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductName
    if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Build -lt 22000)) {
        Write-Fatal "This script targets Windows 11 (build 22000+). Detected: $productName (build $($osVersion.Build))"
    }
    Write-Log "Detected: $productName (build $($osVersion.Build))"
}

# ---------------------------------------------------------------------------
# Usability impact helper
# ---------------------------------------------------------------------------

function Write-UsabilityNote {
    param([string]$Note)
    Write-Host "  [USABILITY] $Note" -ForegroundColor Magenta
}
