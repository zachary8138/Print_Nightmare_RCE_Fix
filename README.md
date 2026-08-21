# Windows 11 PrintNightmare registry remediation

`PrintNightmareFix_win11.ps1` remediates the Point and Print registry exposure
that Tenable reports as plugin **151488** on Windows 11 workstations:

- [Plugin 151488: Windows PrintNightmare Registry Exposure CVE-2021-34527 OOB Security Update RCE](https://www.tenable.com/plugins/nessus/151488)

The July 2021 PrintNightmare update does **not** reset existing Point and Print
policy. If those prompt values were set insecurely (commonly by Group Policy or
an Intune printer profile), a fully patched Windows 11 PC still fails this
check.

This script follows Microsoft CVE-2021-34527, KB5005010, and KB5005652 client
guidance. It does not disable the Print Spooler.

## What Tenable 151488 checks

The plugin reports the host as exposed when either of these values exists under

`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`

and is **not** `0`:

| Value | Insecure examples | Secure state |
|---|---|---|
| `NoWarningNoElevationOnInstall` | `1` (do not show warning or elevation prompt) | `0` (`REG_DWORD`) or not defined |
| `UpdatePromptSettings` | `1` (warning only) or `2` (no warning or elevation) | `0` (`REG_DWORD`) or not defined |

Microsoft’s advisory is the same: non-zero values make a patched system
vulnerable by design.

## What the script changes

1. If `NoWarningNoElevationOnInstall` is present and not `REG_DWORD` `0`, it is
   set to `0`.
2. If `UpdatePromptSettings` is present and not `REG_DWORD` `0`, it is set to
   `0`.
3. `RestrictDriverInstallationToAdministrators` is set to `REG_DWORD` `1`.
   Microsoft documents this as the recommended override so only administrators
   can install printer drivers via Point and Print (KB5005010 step 4 /
   KB5005652). Missing or `0` is corrected; `1` is left unchanged.

The script does **not** create the two Tenable-checked prompt values when they
are absent. Absence is the Microsoft default and is already secure.

The script does **not** delete the `PointAndPrint` key, trusted server lists,
or other printer policy values.

## Operational impact

With `RestrictDriverInstallationToAdministrators = 1` (Windows 11 default after
the August 2021 updates, made explicit here):

- Standard users cannot install or update Point and Print drivers without
  administrator credentials.
- Existing printers that already have a driver on the device continue to work.
- Universal Print, Intune printer deployment, and drivers pre-staged in the
  image are the supported ways to give users printers without reopening this
  exposure.

Microsoft states that no combination of other Point and Print mitigations is
equivalent to keeping this value at `1`. Do not set it to `0` to “make printers
work.”

These registry writes do **not** require a reboot or a Print Spooler restart.

## If necessary: Point and Print Restrictions policy

If Point and Print Restrictions is still set to **Do not show warning or
elevation prompt**, policy refresh will undo the script and 151488 will come
back. Change those prompts to **Show warning and elevation prompt**, or remove
that policy. Standard users will need admin credentials (or Intune/Universal
Print) to install Point and Print drivers — that is the Microsoft-supported
secure behavior.

This applies to Group Policy and to Intune Settings Catalog printer profiles.
Prefer enabling **Limits print driver installation to Administrators** in the
same printer policy set. Assign this script only after printer-deployment
policy has been reviewed, otherwise Intune remediations and Group Policy will
fight.

## Requirements

- Windows 11 (build 22000 or later).
- Windows PowerShell 5.1 or later.
- A 64-bit PowerShell process (avoids WOW64 registry redirection).
- Local Administrator or `SYSTEM` (Intune platform scripts).
- Current Windows 11 security updates already deployed by the organization.

The script remediates the **registry exposure** that plugin 151488 reports. It
does not install KBs. Windows 11 cumulative updates already contain the
CVE-2021-34527 code fix.

## Run manually

1. Confirm current Windows 11 updates are installed.
2. Save the script locally.
3. Open **64-bit Windows PowerShell as Administrator**.
4. If required by policy, sign the script with an approved code-signing
   certificate. Do not permanently weaken the execution policy.
5. Run:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\PrintNightmareFix_win11.ps1
   ```

   `-ExecutionPolicy Bypass` affects only this process invocation. Omit it when
   application control or organizational policy requires a signed script.

6. Review the exit code and log:

   ```powershell
   $LASTEXITCODE
   Get-Content 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\PrintNightmareFix.log'
   ```

## Deploy with Intune (platform script)

**Devices > Scripts and remediations > Platform scripts > Add**

| Setting | Value |
|---|---|
| Run this script using the logged-on credentials | **No** |
| Run script in 64-bit PowerShell host | **Yes** |
| Enforce script signature check | According to organizational signing policy |
| Assignment | Windows 11 workstation device group(s) |

Platform scripts typically run once. Use remediations (below) if a printer GPO
or profile might put the insecure values back.

Exit codes:

- `0`: registry state was already compliant, or values were written and
  verified.
- `1`: not Windows 11, not elevated, 32-bit host, write failure, or
  verification failure.

Intune marks any non-zero exit as **Failed**.

## Optional: Intune remediations (recurring)

**Devices > Scripts and remediations > Remediations**

Run detection and remediation as **64-bit**, **SYSTEM**, on a schedule (for
example daily).

**Detection script** (exit `1` means non-compliant and triggers remediation):

```powershell
$ErrorActionPreference = 'Stop'
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'

function Test-SecurePromptValue {
    param([string]$Name)
    if (-not (Test-Path $path)) { return $true }
    $item = Get-Item -Path $path
    if ($item.GetValueNames() -notcontains $Name) { return $true }
    $kind = $item.GetValueKind($Name).ToString()
    $value = $item.GetValue($Name)
    return ($kind -eq 'DWord' -and [int]$value -eq 0)
}

function Test-RestrictAdmins {
    if (-not (Test-Path $path)) { return $false }
    $item = Get-Item -Path $path
    if ($item.GetValueNames() -notcontains 'RestrictDriverInstallationToAdministrators') { return $false }
    $kind = $item.GetValueKind('RestrictDriverInstallationToAdministrators').ToString()
    $value = $item.GetValue('RestrictDriverInstallationToAdministrators')
    return ($kind -eq 'DWord' -and [int]$value -eq 1)
}

$promptsOk = (Test-SecurePromptValue 'NoWarningNoElevationOnInstall') -and
             (Test-SecurePromptValue 'UpdatePromptSettings')

if ($promptsOk -and (Test-RestrictAdmins)) { exit 0 }
exit 1
```

**Remediation script:** upload `PrintNightmareFix_win11.ps1`.

## Verify on the device

```powershell
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
    Select-Object NoWarningNoElevationOnInstall, UpdatePromptSettings,
                  RestrictDriverInstallationToAdministrators
```

Expected:

- Prompt values either missing or `0`.
- `RestrictDriverInstallationToAdministrators` = `1`.

Then run a credentialed Tenable/Nessus scan and confirm plugin **151488** is
not reported.

## Logging

`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\PrintNightmareFix.log`

The log records Windows edition/build, each value’s before state, writes, and
failures.

## What this script does not cover

- Missing OS updates (separate Tenable bulletin plugins / Microsoft Update).
- Disabling the Print Spooler as a workaround. That breaks printing and is not
  what plugin 151488 measures.
- Print server hardening. This package is for Windows 11 workstations.

## References

- [Tenable plugin 151488](https://www.tenable.com/plugins/nessus/151488)
- [Microsoft CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
- [MSRC clarified guidance for CVE-2021-34527](https://www.microsoft.com/en-us/msrc/blog/2021/07/clarified-guidance-for-cve-2021-34527-windows-print-spooler-vulnerability)
- [KB5005010 — restricting installation of new printer drivers](https://support.microsoft.com/en-us/servicing/os/windows/2021/07/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates)
- [KB5005652 — Point and Print default driver installation behavior (CVE-2021-34481)](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
