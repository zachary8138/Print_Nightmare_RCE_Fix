<#
.SYNOPSIS
    Remediates the PrintNightmare Point and Print registry exposure on Windows 11 workstations.

.DESCRIPTION
    Remediates Tenable Nessus plugin 151488:
      Windows PrintNightmare Registry Exposure CVE-2021-34527 OOB Security Update RCE

    Microsoft's CVE-2021-34527 guidance states that after the security update is installed,
    the host remains exposed if Point and Print prompt settings are non-zero. Tenable 151488
    reports the finding when either value exists and is not 0:

      HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
        NoWarningNoElevationOnInstall  (non-zero = insecure)
        UpdatePromptSettings           (non-zero = insecure)

    Secure state for those two values is REG_DWORD 0, or not defined.

    This script also applies Microsoft KB5005010 / KB5005652 recommended hardening:
      RestrictDriverInstallationToAdministrators = 1 (REG_DWORD)

    That value requires administrator privileges to install or update printer drivers via
    Point and Print, and overrides insecure Point and Print Restrictions policy.

    This script does not:
      - Disable the Print Spooler service
      - Change RPC print endpoints
      - Remove trusted print-server lists under PointAndPrint
      - Install Windows updates (those must already be deployed)

    IMPORTANT PREREQUISITES:
      - Current Windows 11 cumulative updates (CVE-2021-34527 is included in updates
        released on or after 6 July 2021; Windows 11 shipped with this protection).
      - Run in a 64-bit, elevated PowerShell 5.1+ process (SYSTEM for Intune).
      - Remove or correct any GPO / Intune Settings Catalog policy that sets Point and
        Print prompts to "Do not show warning or elevation prompt". Policy refresh will
        otherwise restore the insecure values.
      - No reboot is required for these registry changes.

    Intune deployment settings (Devices > Scripts and remediations > Platform scripts):
      - Run this script using the logged-on credentials: No  (SYSTEM required for HKLM)
      - Run script in 64-bit PowerShell host: Yes
      - Enforce script signature check: per organizational policy

    Exit codes (Intune reports success only on 0):
      0 = Registry configuration is compliant or was successfully remediated
      1 = Unsupported target, prerequisite detection failure, or remediation failure

    Log: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\PrintNightmareFix.log

.NOTES
    Requires: Windows 11, PowerShell 5.1+, elevated/SYSTEM context
    References:
      - https://www.tenable.com/plugins/nessus/151488
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
      - https://www.microsoft.com/en-us/msrc/blog/2021/07/clarified-guidance-for-cve-2021-34527-windows-print-spooler-vulnerability
      - https://support.microsoft.com/en-us/servicing/os/windows/2021/07/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates
      - https://support.microsoft.com/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# --- Configuration (Microsoft CVE-2021-34527 / KB5005010 / KB5005652) ---
$LogPath = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\PrintNightmareFix.log'
$PointAndPrintPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'

# Tenable plugin 151488 flags these when present and not 0.
$TenablePromptValueNames = @(
    'NoWarningNoElevationOnInstall',
    'UpdatePromptSettings'
)

$RestrictValueName = 'RestrictDriverInstallationToAdministrators'
$RestrictSecureValue = 1
$PromptSecureValue = 0

# --- Logging ---
function Ensure-LogDirectory {
    $logDir = Split-Path -Parent $LogPath
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
}

function Write-RemediationLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')][string]$Type = 'INFO'
    )
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Type] $Message"
    Add-Content -Path $LogPath -Value $line -Encoding utf8
}

# --- Environment checks ---
function Test-IsWindows11 {
    try {
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $productName = ($cv.ProductName -as [string])

        if ($productName -and $productName -match 'Windows\s+11') { return $true }

        $build = [int]$cv.CurrentBuildNumber
        return ($build -ge 22000)
    }
    catch {
        Write-RemediationLog "Windows version detection failed: $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-RegistryValueExists {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -Path $Path)) { return $false }

    try {
        $valueNames = @((Get-Item -Path $Path -ErrorAction Stop).GetValueNames())
        return ($valueNames -contains $Name)
    }
    catch {
        return $false
    }
}

function Get-RegistryValueKind {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-RegistryValueExists -Path $Path -Name $Name)) { return $null }
    try {
        return (Get-Item -Path $Path -ErrorAction Stop).GetValueKind($Name).ToString()
    }
    catch {
        return $null
    }
}

function Get-RegistryDWord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-RegistryValueExists -Path $Path -Name $Name)) { return $null }

    try {
        $raw = (Get-Item -Path $Path -ErrorAction Stop).GetValue($Name)
        if ($null -eq $raw) { return $null }
        if ($raw -is [int] -or $raw -is [long] -or $raw -is [uint32]) {
            return [int]$raw
        }
        return $null
    }
    catch {
        return $null
    }
}

function Set-VerifiedRegistryDWord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$Value
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    # New-ItemProperty -Force creates or replaces the value and guarantees REG_DWORD.
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    $read = Get-RegistryDWord -Path $Path -Name $Name
    $kind = Get-RegistryValueKind -Path $Path -Name $Name

    if ($read -ne $Value -or $kind -ne 'DWord') {
        Write-RemediationLog "Registry mismatch for $Name at $Path. Expected DWord $Value, read $kind $read." 'ERROR'
        return $false
    }

    Write-RemediationLog "Set $Name = $Value (REG_DWORD) at $Path." 'SUCCESS'
    return $true
}

function Get-PromptValueState {
    param(
        [Parameter(Mandatory = $true)][string]$Name
    )

    $exists = Test-RegistryValueExists -Path $PointAndPrintPath -Name $Name
    $kind = Get-RegistryValueKind -Path $PointAndPrintPath -Name $Name
    $value = Get-RegistryDWord -Path $PointAndPrintPath -Name $Name

    # Microsoft and Tenable 151488: not defined, or REG_DWORD 0, is secure.
    # Any other present value (non-zero, empty, or wrong type) is treated as exposed.
    $compliant = (-not $exists) -or ($kind -eq 'DWord' -and $value -eq $PromptSecureValue)

    return [pscustomobject]@{
        Name       = $Name
        Exists     = $exists
        Kind       = $kind
        Value      = $value
        Compliant  = $compliant
        NeedsWrite = ($exists -and -not $compliant)
    }
}

function Get-RestrictValueState {
    $exists = Test-RegistryValueExists -Path $PointAndPrintPath -Name $RestrictValueName
    $kind = Get-RegistryValueKind -Path $PointAndPrintPath -Name $RestrictValueName
    $value = Get-RegistryDWord -Path $PointAndPrintPath -Name $RestrictValueName
    $compliant = ($exists -and $kind -eq 'DWord' -and $value -eq $RestrictSecureValue)

    return [pscustomobject]@{
        Name      = $RestrictValueName
        Exists    = $exists
        Kind      = $kind
        Value     = $value
        Compliant = $compliant
    }
}

function Write-ValueState {
    param(
        [Parameter(Mandatory = $true)]$State
    )

    if (-not $State.Exists) {
        Write-RemediationLog "$($State.Name) is not defined." 'INFO'
        return
    }

    $displayValue = if ($null -eq $State.Value) { '<unreadable>' } else { [string]$State.Value }
    $displayKind = if ([string]::IsNullOrWhiteSpace($State.Kind)) { 'Unknown' } else { $State.Kind }
    Write-RemediationLog "$($State.Name) = $displayValue ($displayKind)." 'INFO'
}

# --- Main ---
try {
    Ensure-LogDirectory
    Write-RemediationLog 'PrintNightmareFix_win11.ps1 started.' 'INFO'

    if (-not (Test-IsWindows11)) {
        Write-RemediationLog 'Target is not Windows 11. No changes were made.' 'ERROR'
        exit 1
    }

    if (-not (Test-IsElevated)) {
        Write-RemediationLog 'Script is not running with administrative/SYSTEM privileges. HKLM changes will fail.' 'ERROR'
        exit 1
    }

    if (-not [Environment]::Is64BitProcess) {
        Write-RemediationLog 'Script is running in a 32-bit PowerShell process. Run it in 64-bit Windows PowerShell to avoid registry redirection.' 'ERROR'
        exit 1
    }

    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    Write-RemediationLog "Environment: $($cv.ProductName) build $($cv.CurrentBuildNumber), 64-bit elevated PowerShell." 'INFO'
    Write-RemediationLog "Policy path: $PointAndPrintPath" 'INFO'

    $promptStates = @(
        foreach ($name in $TenablePromptValueNames) {
            Get-PromptValueState -Name $name
        }
    )
    $restrictState = Get-RestrictValueState

    foreach ($state in $promptStates) { Write-ValueState -State $state }
    Write-ValueState -State $restrictState

    $promptsCompliant = ($promptStates | Where-Object { -not $_.Compliant }).Count -eq 0
    $allCompliant = $promptsCompliant -and $restrictState.Compliant

    if ($allCompliant) {
        Write-RemediationLog 'Point and Print registry configuration is already compliant with Tenable plugin 151488 and Microsoft KB5005010/KB5005652.' 'SUCCESS'
        Write-RemediationLog 'PrintNightmareFix_win11.ps1 complete.' 'INFO'
        exit 0
    }

    $anyFailures = $false

    foreach ($state in $promptStates) {
        if ($state.NeedsWrite) {
            Write-RemediationLog "$($state.Name) is present and insecure. Setting REG_DWORD $PromptSecureValue per Microsoft CVE-2021-34527 guidance." 'WARNING'
            if (-not (Set-VerifiedRegistryDWord -Path $PointAndPrintPath -Name $state.Name -Value $PromptSecureValue)) {
                $anyFailures = $true
            }
        }
        elseif (-not $state.Exists) {
            Write-RemediationLog "$($state.Name) is not defined (secure default). Value will not be created." 'INFO'
        }
    }

    if (-not $restrictState.Compliant) {
        Write-RemediationLog "$RestrictValueName is missing or not 1. Setting REG_DWORD $RestrictSecureValue per KB5005652." 'INFO'
        if (-not (Set-VerifiedRegistryDWord -Path $PointAndPrintPath -Name $RestrictValueName -Value $RestrictSecureValue)) {
            $anyFailures = $true
        }
    }

    $postPromptStates = @(
        foreach ($name in $TenablePromptValueNames) {
            Get-PromptValueState -Name $name
        }
    )
    $postRestrictState = Get-RestrictValueState
    $postCompliant = (($postPromptStates | Where-Object { -not $_.Compliant }).Count -eq 0) -and $postRestrictState.Compliant

    if (-not $postCompliant) {
        Write-RemediationLog 'Post-remediation compliance check failed.' 'ERROR'
        $anyFailures = $true
    }

    if ($anyFailures) {
        Write-RemediationLog 'Remediation finished with failures. Review the log, confirm 64-bit SYSTEM context, and check for a conflicting printer GPO or Intune profile.' 'ERROR'
        exit 1
    }

    Write-RemediationLog 'Registry remediation applied successfully. No reboot is required for these Point and Print values.' 'SUCCESS'
    Write-RemediationLog 'If a domain GPO or Intune Settings Catalog profile still sets insecure Point and Print prompts, that policy will overwrite these values on the next refresh.' 'WARNING'
    Write-RemediationLog 'PrintNightmareFix_win11.ps1 complete.' 'INFO'
    exit 0
}
catch {
    try {
        Write-RemediationLog "Unhandled error: $($_.Exception.Message)" 'ERROR'
    }
    catch {
        # Last-resort if logging itself fails
    }
    exit 1
}
