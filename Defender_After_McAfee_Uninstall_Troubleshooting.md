# Troubleshooting: Microsoft Defender does not start after McAfee/Trellix uninstall

## Scenario

When trying to uninstall a 3rd Party AV like here McAfee/Trellix AV. The expectation was that Microsoft Defender Antivirus would automatically become active again. However, Windows Security shows no active protection, and `Get-MpComputerStatus` reports Defender as not running.

Typical symptoms:

```text
AMServiceEnabled              : False
AntivirusEnabled              : False
AntispywareEnabled            : False
RealTimeProtectionEnabled     : False
OnAccessProtectionEnabled     : False
AMRunningMode                 : Not running
DefenderSignaturesOutOfDate   : True
AntivirusSignatureLastUpdated :
```

Another common service state:

```text
WinDefend              Manual     Stopped
WdFilter               Manual     Stopped
WdNisSvc               Manual     Stopped
WdNisDrv               Manual     Stopped
SecurityHealthService  Manual     Running
wscsvc                 Automatic  Running
```

## Important interpretation

If `AMRunningMode` is `Not running`, Defender is not simply waiting a few minutes to become active. The device should be treated as unprotected until Defender reports:

```text
AMRunningMode              : Normal
AMServiceEnabled           : True
AntivirusEnabled           : True
RealTimeProtectionEnabled  : True
OnAccessProtectionEnabled  : True
```

Until then, isolate the device if possible, especially if it is exposed to user traffic, email, internet browsing, or untrusted files.

---

## 1. Check current Defender status

Run PowerShell as Administrator.

```powershell
Get-MpComputerStatus | Select-Object `
    AMServiceEnabled,
    AntivirusEnabled,
    AntispywareEnabled,
    RealTimeProtectionEnabled,
    OnAccessProtectionEnabled,
    AMRunningMode,
    AMEngineVersion,
    AMProductVersion,
    AMServiceVersion,
    DefenderSignaturesOutOfDate,
    AntivirusSignatureLastUpdated
```

### Interpretation

```text
AMRunningMode = Normal       -> Defender is active
AMRunningMode = Passive Mode -> Defender is installed but not primary AV
AMRunningMode = Not running  -> Defender is not protecting the device
```

If `AMEngineVersion` or `AMServiceVersion` shows `0.0.0.0`, the Defender engine/signature state may be broken or missing.

---

## 2. Check Defender-related services

```powershell
Get-Service WinDefend, WdBoot, WdFilter, WdNisSvc, WdNisDrv, SecurityHealthService, wscsvc |
Format-Table DisplayName, Name, StartType, Status -AutoSize
```

Important services and drivers:

```text
WinDefend              Microsoft Defender Antivirus Service
WdFilter               Microsoft Defender Antivirus Mini-Filter Driver
WdBoot                 Microsoft Defender Antivirus Boot Driver
WdNisSvc               Microsoft Defender Antivirus Network Inspection Service
WdNisDrv               Microsoft Defender Antivirus Network Inspection Driver
SecurityHealthService  Windows Security Health Service
wscsvc                 Windows Security Center
```

A healthy client should not have all Defender components stopped.

---

## 3. Check what Windows Security Center sees as antivirus provider

This is important after removing McAfee/Trellix.

```powershell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
Select-Object displayName, productState, pathToSignedProductExe, pathToSignedReportingExe |
Format-List
```

### Interpretation

If you still see entries like these, Windows may still believe the old AV product is installed:

```text
McAfee
Trellix
Endpoint Security
ENS
VirusScan
```

Recommended action:

1. Reboot once after the McAfee/Trellix uninstall.
2. Run the command again.
3. If McAfee/Trellix is still listed, use the official McAfee/Trellix cleanup or removal procedure.

If only `Windows Defender` is listed but Defender is still not running, focus on policy, service startup, and Defender repair.

---

## 4. Try starting Defender

Do not worry too much if changing the startup type fails with `Access denied`. Defender services are protected and local administrators may not be allowed to modify them directly.

First try starting the service:

```powershell
Start-Service WinDefend -ErrorAction Stop
Start-Service WdNisSvc -ErrorAction SilentlyContinue
```

Then verify the status:

```powershell
Get-Service WinDefend, WdFilter, WdNisSvc, SecurityHealthService, wscsvc |
Format-Table Name, StartType, Status -AutoSize

Get-MpComputerStatus | Select-Object `
    AMServiceEnabled,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    OnAccessProtectionEnabled,
    AMRunningMode,
    AMEngineVersion,
    AMServiceVersion,
    AntivirusSignatureLastUpdated
```

If `Start-Service WinDefend` fails, capture the full error:

```powershell
try {
    Start-Service WinDefend -ErrorAction Stop
}
catch {
    $_ | Format-List * -Force
    $_.Exception | Format-List * -Force
}
```

Common error interpretation:

```text
Access denied             -> policy, protection mechanism, or security control
Service disabled          -> service or policy configuration issue
Cannot find file/path     -> Defender platform or component damage
Dependency failed         -> related service or driver problem
```

---

## 5. Check Defender policy settings

Defender may have been disabled previously because McAfee/Trellix was the primary AV solution. This can happen through GPO, Intune, security baseline, RMM, PowerShell, WMI, or registry configuration.

```powershell
$PolicyPaths = @(
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection',
  'HKLM:\SOFTWARE\Microsoft\Windows Defender',
  'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
)

foreach ($Path in $PolicyPaths) {
    if (Test-Path $Path) {
        Write-Host "`n===== $Path =====" -ForegroundColor Cyan
        Get-ItemProperty $Path | Format-List
    }
}
```

Look especially for:

```text
DisableAntiSpyware
DisableAntivirus
DisableRealtimeMonitoring
ForceDefenderPassiveMode
PassiveMode
```

Problematic values usually look like:

```text
DisableAntiSpyware        = 1
DisableAntivirus          = 1
DisableRealtimeMonitoring = 1
ForceDefenderPassiveMode  = 1
PassiveMode               = 1
```

Do not blindly delete these values before identifying where they come from. If they are managed by GPO, Intune, RMM, or a security baseline, they may return automatically.

---

## 6. Generate a GPO report

Use this to check whether Group Policy is disabling Defender.

```powershell
New-Item -ItemType Directory -Path C:\Temp -Force | Out-Null

gpresult /h C:\Temp\gpresult.html
Start-Process C:\Temp\gpresult.html
```

Search the report for:

```text
Microsoft Defender Antivirus
Windows Defender
Turn off Microsoft Defender Antivirus
Real-time Protection
Passive Mode
DisableAntiSpyware
DisableRealtimeMonitoring
```

---

## 7. Check service configuration without changing it

```powershell
sc.exe query WinDefend
sc.exe qc WinDefend

reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv"
```

Service `Start` value interpretation:

```text
Start = 2 -> Automatic
Start = 3 -> Manual
Start = 4 -> Disabled
```

If `WinDefend` has `Start = 4`, something has disabled the service.

---

## 8. Repair Defender definitions and signatures

If Defender shows missing or broken engine/signature information, try resetting definitions and updating signatures.

```powershell
cd "$env:ProgramFiles\Windows Defender"

.\MpCmdRun.exe -RemoveDefinitions -All
.\MpCmdRun.exe -SignatureUpdate
```

Then check status again:

```powershell
Get-MpComputerStatus | Select-Object `
    AMEngineVersion,
    AMProductVersion,
    AMServiceEnabled,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    OnAccessProtectionEnabled,
    AMRunningMode,
    AntivirusSignatureLastUpdated
```

You can also try:

```powershell
Update-MpSignature -Verbose
```

If `Update-MpSignature` fails with an error such as `0x80004003`, continue with event log and component repair steps below.

---

## 9. Check Defender event logs

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 100 |
Select-Object TimeCreated, Id, ProviderName, Message |
Format-List
```

Also check service control events:

```powershell
Get-WinEvent -LogName System -MaxEvents 200 |
Where-Object {
    $_.ProviderName -eq 'Service Control Manager' -and
    $_.Message -match 'WinDefend|WdFilter|WdNisSvc|WdNisDrv|Defender'
} |
Select-Object TimeCreated, Id, ProviderName, Message |
Format-List
```

Look for errors related to:

```text
WinDefend
WdFilter
WdNisSvc
WdNisDrv
Microsoft Defender Antivirus Service
Microsoft Defender Antivirus Mini-Filter Driver
service failed to start
access denied
cannot find the file specified
```

---

## 10. Check whether McAfee/Trellix left logs or management actions

This is useful if you need to confirm whether the uninstall came from a user, ePO, Intune, SCCM, or another management platform.

### Windows Installer events

```powershell
$Start = (Get-Date).AddHours(-4)
$End   = Get-Date

Get-WinEvent -FilterHashtable @{
    LogName      = 'Application'
    ProviderName = 'MsiInstaller'
    StartTime    = $Start
    EndTime      = $End
} | Where-Object {
    $_.Message -match 'McAfee|Trellix|Endpoint Security|ENS|VirusScan|Agent|MFE|MA'
} | Select-Object TimeCreated, Id, ProviderName, Message |
Format-List
```

### Service Control Manager events

```powershell
$Start = (Get-Date).AddHours(-4)

Get-WinEvent -FilterHashtable @{
    LogName   = 'System'
    StartTime = $Start
} | Where-Object {
    $_.ProviderName -eq 'Service Control Manager' -and
    $_.Message -match 'McAfee|Trellix|mfe|masvc|macmnsvc|mfemms|mfetp|mfewc|McShield|Framework'
} | Select-Object TimeCreated, Id, ProviderName, Message |
Format-List
```

### McAfee/Trellix local logs

```powershell
$Start = (Get-Date).AddHours(-4)

$logPaths = @(
  'C:\ProgramData\McAfee',
  'C:\ProgramData\Trellix',
  'C:\Program Files\McAfee',
  'C:\Program Files\Trellix',
  'C:\Program Files\Common Files\McAfee',
  'C:\Program Files (x86)\McAfee',
  'C:\Program Files (x86)\Trellix'
)

foreach ($path in $logPaths) {
    if (Test-Path $path) {
        Write-Host "`n===== $path =====" -ForegroundColor Cyan
        Get-ChildItem $path -Recurse -Include *.log,*.txt -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Start } |
            Sort-Object LastWriteTime -Descending |
            Select-Object LastWriteTime, FullName
    }
}
```

Search those logs for removal indicators:

```powershell
Select-String -Path 'C:\ProgramData\McAfee\*.log',
                    'C:\ProgramData\Trellix\*.log',
                    'C:\ProgramData\McAfee\**\*.log',
                    'C:\ProgramData\Trellix\**\*.log' `
    -Pattern 'uninstall','remove','removed','msiexec','rollback','failed','success','error','policy','task','deployment' `
    -ErrorAction SilentlyContinue |
Select-Object Path, LineNumber, Line |
Format-List
```

---

## 11. Check Intune or ConfigMgr/SCCM involvement

### Intune Management Extension

```powershell
Select-String -Path 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\*.log' `
    -Pattern 'McAfee','Trellix','Endpoint Security','ENS','uninstall','remove','msiexec','Defender','DisableAntiSpyware','DisableRealtimeMonitoring' `
    -ErrorAction SilentlyContinue |
Select-Object Path, LineNumber, Line |
Format-List
```

### ConfigMgr / SCCM

```powershell
Select-String -Path 'C:\Windows\CCM\Logs\*.log' `
    -Pattern 'McAfee','Trellix','Endpoint Security','ENS','uninstall','remove','msiexec','Defender','DisableAntiSpyware','DisableRealtimeMonitoring' `
    -ErrorAction SilentlyContinue |
Select-Object Path, LineNumber, Line |
Format-List
```

Relevant SCCM logs may include:

```text
AppEnforce.log
ExecMgr.log
CcmExec.log
CIAgent.log
UpdatesDeployment.log
```

---

## 12. Repair Windows components

If Defender is still not running and policies do not explain it, repair Windows components.

```powershell
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow
```

Reboot afterwards.

Then check again:

```powershell
Get-MpComputerStatus | Select-Object `
    AMServiceEnabled,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    OnAccessProtectionEnabled,
    AMRunningMode,
    AMEngineVersion,
    AMServiceVersion,
    AntivirusSignatureLastUpdated

Get-Service WinDefend, WdFilter, WdNisSvc, SecurityHealthService, wscsvc |
Format-Table Name, StartType, Status -AutoSize
```

---

## 13. One-shot diagnostic collection command

This command collects the most relevant local state into a text file on the desktop.

```powershell
$OutFile = "$env:USERPROFILE\Desktop\Defender-Troubleshooting-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

"===== Microsoft Defender computer status =====" | Out-File $OutFile
Get-MpComputerStatus | Out-File $OutFile -Append

"`n===== Defender and Security Center services =====" | Out-File $OutFile -Append
Get-Service WinDefend, WdBoot, WdFilter, WdNisSvc, WdNisDrv, SecurityHealthService, wscsvc |
Format-Table DisplayName, Name, StartType, Status -AutoSize | Out-String | Out-File $OutFile -Append

"`n===== Security Center AV products =====" | Out-File $OutFile -Append
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
Select-Object displayName, productState, pathToSignedProductExe, pathToSignedReportingExe, timestamp |
Format-List | Out-String | Out-File $OutFile -Append

"`n===== Defender policy registry keys =====" | Out-File $OutFile -Append
$PolicyPaths = @(
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection',
  'HKLM:\SOFTWARE\Microsoft\Windows Defender',
  'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
)
foreach ($Path in $PolicyPaths) {
    if (Test-Path $Path) {
        "`n===== $Path =====" | Out-File $OutFile -Append
        Get-ItemProperty $Path | Format-List | Out-String | Out-File $OutFile -Append
    }
}

"`n===== WinDefend service query =====" | Out-File $OutFile -Append
sc.exe query WinDefend | Out-File $OutFile -Append
sc.exe qc WinDefend | Out-File $OutFile -Append

"`n===== Recent Defender Operational events =====" | Out-File $OutFile -Append
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, ProviderName, Message |
Format-List | Out-String | Out-File $OutFile -Append

"`n===== Recent Service Control Manager Defender events =====" | Out-File $OutFile -Append
Get-WinEvent -LogName System -MaxEvents 200 -ErrorAction SilentlyContinue |
Where-Object {
    $_.ProviderName -eq 'Service Control Manager' -and
    $_.Message -match 'WinDefend|WdFilter|WdNisSvc|WdNisDrv|Defender'
} |
Select-Object TimeCreated, Id, ProviderName, Message |
Format-List | Out-String | Out-File $OutFile -Append

Write-Host "Diagnostic output written to: $OutFile" -ForegroundColor Green
```

---

## 14. Recommended operational flow

```text
1. Treat the device as unprotected.
2. Isolate the device if risk is high.
3. Reboot once after McAfee/Trellix uninstall.
4. Check Get-MpComputerStatus.
5. Check SecurityCenter2 AntivirusProduct.
6. If McAfee/Trellix is still listed, clean up McAfee/Trellix remnants.
7. If only Windows Defender is listed, check Defender services.
8. Check Defender policy keys and GPO/Intune/RMM sources.
9. Try to start WinDefend.
10. Reset Defender definitions and update signatures.
11. Review Defender and Service Control Manager events.
12. Run DISM and SFC repair if needed.
13. Reboot and verify Defender is active.
```

---

## 15. Healthy final validation

The device should only be considered protected when this command:

```powershell
Get-MpComputerStatus | Select-Object `
    AMServiceEnabled,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    OnAccessProtectionEnabled,
    AMRunningMode,
    AMEngineVersion,
    AMServiceVersion,
    AntivirusSignatureLastUpdated
```

returns values similar to:

```text
AMServiceEnabled           : True
AntivirusEnabled           : True
RealTimeProtectionEnabled  : True
OnAccessProtectionEnabled  : True
AMRunningMode              : Normal
AMEngineVersion            : <valid version>
AMServiceVersion           : <valid version>
AntivirusSignatureLastUpdated : <recent timestamp>
```

---

## Notes

- After uninstalling a third-party AV, Defender usually should become active automatically, but a reboot is often required in practice.
- If Defender remains `Not running`, do not wait indefinitely. Investigate policy, service state, Defender component health, and leftover AV registration.
- `Set-Service WinDefend -StartupType Automatic` may return `Access denied` even in an elevated PowerShell session because Defender services are protected.
- The more important test is whether `Start-Service WinDefend` works and whether `Get-MpComputerStatus` changes to `AMRunningMode : Normal`.
- If Defender is managed by Intune, GPO, security baselines, or RMM, local changes may be reverted.
