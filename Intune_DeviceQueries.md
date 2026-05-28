# Intune Device Queries for Microsoft Defender for Endpoint Migration

This README contains useful Microsoft Intune **Device query** snippets for a Windows 11 migration from **Trellix/McAfee** to **Microsoft Defender for Endpoint (MDE)** and **Microsoft Defender Antivirus**.

The goal is to support rollout validation, troubleshooting, and device readiness checks during the migration.

> Scope context: Windows 11 clients are Intune-managed, hybrid joined, and onboarded to Microsoft Defender for Endpoint via Intune. Trellix/McAfee is removed in controlled rollout waves so Microsoft Defender Antivirus can switch from passive mode to active mode.

---

## Important notes

There are two Intune query experiences that are relevant:

| Query type | Portal location | Use case | Notes |
|---|---|---|---|
| **Device query for multiple devices** | `Intune admin center` -> `Devices` -> `Device query` | Fleet-level inventory and rollout overview | Useful for OS, TPM, disk, hardware, and inventory trends. Windows devices require an inventory/properties catalog policy. |
| **Single device query** | `Intune admin center` -> `Devices` -> `Windows` -> select device -> `Device query` | Real-time troubleshooting on one selected device | Useful for services, processes, registry keys, files, and Windows event logs. |

Important limitations:

- Intune Device query uses a supported subset of KQL, not the full Microsoft Defender Advanced Hunting schema.
- Some Defender-specific runtime data is easier to validate with PowerShell, Defender Advanced Hunting, or the Defender portal.
- Queries for services, processes, registry keys, files, and Windows events are generally **single device query** checks.
- Device query depends on the device being reachable and able to respond to Intune in real time.

---

## Recommended migration validation areas

During the Defender migration, validate at least the following:

| Area | Why it matters |
|---|---|
| Windows 11 inventory | Confirms that the device is in migration scope. |
| Hybrid / Entra device mapping | Needed for Entra device groups and Intune assignment. |
| Intune management state | Required for policy deployment. |
| MDE sensor service | Confirms Defender for Endpoint onboarding runtime health. |
| Defender Antivirus service | Confirms Defender AV service state. |
| Defender AV active/passive state | Confirms whether Defender is still passive or active after Trellix removal. |
| Trellix/McAfee services and processes | Confirms whether legacy AV is still present or running. |
| ASR audit telemetry | Supports later hardening planning. |
| BitLocker/TPM baseline | Useful readiness context, even if not in AV migration scope. |
| Disk space and OS build | Helps detect devices likely to fail policy/application deployment. |

---

# 1. Fleet-level queries: Device query for multiple devices

Use these in:

```text
Intune admin center -> Devices -> Device query
```

These queries are useful for rollout planning and broad inventory checks.

---

## 1.1 Count devices by OS version

Purpose: Identify Windows 11 build distribution before rollout.

```kql
OsVersion
| summarize DeviceCount = count() by OsName, OsVersion, Architecture
| order by DeviceCount desc
```

---

## 1.2 List Windows 11 devices with OS details

Purpose: Export a basic Windows 11 inventory for rollout planning.

```kql
OsVersion
| where OsName contains "Windows"
| project Device, OsName, OsVersion, MajorVersion, MinorVersion, Architecture, InstallDateTime
| order by OsVersion asc
```

---

## 1.3 Identify non-Windows devices in inventory

Purpose: Ensure migration queries and rollout groups are focused on Windows clients only.

```kql
OsVersion
| where OsName !contains "Windows"
| project Device, OsName, OsVersion, Architecture
| order by OsName asc
```

---

## 1.4 Count devices by architecture

Purpose: Identify x64 vs ARM64 devices before policy rollout or app deployment.

```kql
Cpu
| summarize DeviceCount = count() by Architecture
| order by DeviceCount desc
```

---

## 1.5 List ARM64 devices

Purpose: Identify devices that may need special handling for tools, scripts, or agent packages.

```kql
Cpu
| where Architecture == "ARM64"
| project Device, Manufacturer, Model, Architecture, CoreCount, LogicalProcessorCount
| order by Device asc
```

---

## 1.6 Device hardware overview

Purpose: Get a broad hardware baseline for rollout support.

```kql
SystemEnclosure
| project Device, Manufacturer, Model, SerialNumber, Sku, Status
| order by Manufacturer asc, Model asc
```

---

## 1.7 TPM readiness overview

Purpose: Validate TPM status as general Windows security readiness context.

```kql
Tpm
| project Device, Enabled, Activated, Owned, Manufacturer, ManufacturerVersion, SpecVersion
| order by Enabled asc, Activated asc, Owned asc
```

---

## 1.8 Devices with TPM not enabled, activated, or owned

Purpose: Identify devices with platform security issues.

```kql
Tpm
| where Enabled != true or Activated != true or Owned != true
| project Device, Enabled, Activated, Owned, Manufacturer, ManufacturerVersion, SpecVersion
| order by Device asc
```

---

## 1.9 BitLocker protection status

Purpose: Check disk encryption state as general security readiness context.

```kql
EncryptableVolume
| project Device, WindowsDriveLetter, ProtectionStatus, EncryptionMethod, EncryptionPercentage, Locked
| order by Device asc, WindowsDriveLetter asc
```

---

## 1.10 Devices with unprotected volumes

Purpose: Identify devices where BitLocker is not fully protected.

```kql
EncryptableVolume
| where ProtectionStatus != "PROTECTED"
| project Device, WindowsDriveLetter, ProtectionStatus, EncryptionMethod, EncryptionPercentage, Locked
| order by Device asc
```

---

## 1.11 Devices with low free disk space on C:

Purpose: Detect devices that may have issues during uninstall/reboot/update operations.

```kql
LogicalDrive
| where DriveIdentifier == "C:"
| project Device, DriveIdentifier, FileSystem, FreeSpaceGB = FreeSpaceBytes / (1000 * 1000 * 1000), DiskSizeGB = DiskSizeBytes / (1000 * 1000 * 1000)
| where FreeSpaceGB < 10
| order by FreeSpaceGB asc
```

---

## 1.12 Disk space overview for C:

Purpose: General health check before Trellix removal waves.

```kql
LogicalDrive
| where DriveIdentifier == "C:"
| project Device, DriveIdentifier, FileSystem, FreeSpaceGB = FreeSpaceBytes / (1000 * 1000 * 1000), DiskSizeGB = DiskSizeBytes / (1000 * 1000 * 1000)
| order by FreeSpaceGB asc
```

---

## 1.13 Installed Windows updates overview

Purpose: Review installed hotfixes and patch currency.

```kql
WindowsQfe
| project Device, HotFixId, QfeDescription, InstalledDate, InstalledByUserAccount
| order by InstalledDate desc
```

---

## 1.14 Recently installed Windows updates

Purpose: Identify devices recently patched before or during rollout.

```kql
WindowsQfe
| where InstalledDate >= ago(30d)
| project Device, HotFixId, QfeDescription, InstalledDate, InstalledByUserAccount
| order by InstalledDate desc
```

---

## 1.15 Count devices by time zone

Purpose: Useful for rollout wave planning across locations.

```kql
Time
| summarize DeviceCount = count() by TimeZone
| order by DeviceCount desc
```

---

# 2. Single-device queries: Defender and Trellix troubleshooting

Use these in:

```text
Intune admin center -> Devices -> Windows -> select device -> Device query
```

These are useful for validating an individual device before and after Trellix removal.

---

## 2.1 Check Microsoft Defender for Endpoint Sense service

Purpose: Confirm that the MDE sensor service exists and is running.

Expected state after successful MDE onboarding:

```text
ServiceName = Sense
State       = RUNNING
StartMode   = AUTO_START or DEMAND_START depending on configuration/state
```

Query:

```kql
WindowsService
| where ServiceName == "Sense"
| project ServiceName, DisplayName, State, StartMode, ProcessId, Path, WindowsUserAccount
```

---

## 2.2 Check Microsoft Defender Antivirus service

Purpose: Confirm that the Defender Antivirus service exists and is running.

Expected state:

```text
ServiceName = WinDefend
State       = RUNNING
```

Query:

```kql
WindowsService
| where ServiceName == "WinDefend"
| project ServiceName, DisplayName, State, StartMode, ProcessId, Path, WindowsUserAccount
```

---

## 2.3 Check Defender Network Inspection Service

Purpose: Validate the Defender Network Inspection Service.

```kql
WindowsService
| where ServiceName == "WdNisSvc"
| project ServiceName, DisplayName, State, StartMode, ProcessId, Path, WindowsUserAccount
```

---

## 2.4 Check Windows Firewall service

Purpose: Validate the Windows Defender Firewall service as supporting endpoint security context.

```kql
WindowsService
| where ServiceName == "mpssvc"
| project ServiceName, DisplayName, State, StartMode, ProcessId, Path, WindowsUserAccount
```

---

## 2.5 Check all Defender-related services

Purpose: Quick overview of Defender and security-related Microsoft services.

```kql
WindowsService
| where ServiceName contains "WinDefend" or ServiceName contains "Sense" or ServiceName contains "WdNis" or DisplayName contains "Defender"
| project ServiceName, DisplayName, State, StartMode, ProcessId, Path
| order by ServiceName asc
```

---

## 2.6 Check Trellix/McAfee services

Purpose: Confirm whether legacy AV components are still installed or running.

```kql
WindowsService
| where DisplayName contains "Trellix" or DisplayName contains "McAfee" or ServiceName contains "mfe" or ServiceName contains "macmn" or ServiceName contains "masvc"
| project ServiceName, DisplayName, State, StartMode, ProcessId, Path, WindowsUserAccount
| order by ServiceName asc
```

---

## 2.7 Check running Trellix/McAfee processes

Purpose: Detect active legacy AV processes after uninstall or during coexistence.

```kql
Process
| where ProcessName contains "mfe" or ProcessName contains "mcshield" or ProcessName contains "masvc" or ProcessName contains "macmn" or ProcessName contains "Trellix" or ProcessName contains "McAfee"
| project ProcessName, ProcessId, Path, CommandLine, WindowsUserAccount, StartDateTime, WorkingSetSizeBytes
| order by ProcessName asc
```

---

## 2.8 Check running Defender-related processes

Purpose: Confirm that Defender/MDE processes are present.

```kql
Process
| where ProcessName contains "MsMpEng" or ProcessName contains "NisSrv" or ProcessName contains "Sense" or ProcessName contains "SecurityHealth"
| project ProcessName, ProcessId, Path, CommandLine, WindowsUserAccount, StartDateTime, WorkingSetSizeBytes
| order by ProcessName asc
```

---

## 2.9 Check Defender platform folder

Purpose: Validate whether Defender platform files are present.

```kql
FileInfo('C:\\ProgramData\\Microsoft\\Windows Defender\\Platform')
| project Path, FileName, Directory, SizeBytes, CreatedDateTime, LastModifiedDateTime, ProductName, ProductVersion, FileVersion
| order by LastModifiedDateTime desc
| take 50
```

---

## 2.10 Check Defender executable

Purpose: Validate Defender engine executable metadata.

```kql
FileInfo('C:\\ProgramData\\Microsoft\\Windows Defender\\Platform')
| where FileName == "MsMpEng.exe"
| project Path, FileName, SizeBytes, CreatedDateTime, LastModifiedDateTime, ProductName, ProductVersion, FileVersion
| order by LastModifiedDateTime desc
```

---

## 2.11 Check Defender base registry key

Purpose: Inspect Defender registry values on a selected device.

```kql
WindowsRegistry('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender')
| project RegistryKey, ValueName, ValueType, ValueData
| order by RegistryKey asc, ValueName asc
```

---

## 2.12 Check Defender real-time protection registry values

Purpose: Inspect real-time protection related Defender registry values.

```kql
WindowsRegistry('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection')
| project RegistryKey, ValueName, ValueType, ValueData
| order by ValueName asc
```

---

## 2.13 Check Defender cloud protection / SpyNet registry values

Purpose: Inspect cloud-delivered protection related registry values.

```kql
WindowsRegistry('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\SpyNet')
| project RegistryKey, ValueName, ValueType, ValueData
| order by ValueName asc
```

---

## 2.14 Check Defender policy manager values

Purpose: Inspect policy-applied Defender settings.

```kql
WindowsRegistry('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Policy Manager')
| project RegistryKey, ValueName, ValueType, ValueData
| order by RegistryKey asc, ValueName asc
```

---

## 2.15 Check ASR rule policy registry values

Purpose: Validate whether ASR rule configuration exists locally.

```kql
WindowsRegistry('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules')
| project RegistryKey, ValueName, ValueType, ValueData
| order by ValueName asc
```

Expected ASR value meanings commonly used in policy contexts:

| Value | Meaning |
|---|---|
| `0` | Disabled |
| `1` | Block |
| `2` | Audit |
| `6` | Warn |

For this project, ASR rules should be configured as **audit** during rollout.

---

## 2.16 Check Defender exclusions in registry

Purpose: Review local Defender exclusions. Use this carefully; exclusions should be minimal and justified.

```kql
WindowsRegistry('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions')
| project RegistryKey, ValueName, ValueType, ValueData
| order by RegistryKey asc, ValueName asc
```

---

## 2.17 Check Defender operational event log

Purpose: Review recent Defender operational events on one device.

```kql
WindowsEvent('Microsoft-Windows-Windows Defender/Operational', 1d)
| project LoggedDateTime, EventId, Level, ProviderName, Message
| order by LoggedDateTime desc
| take 50
```

---

## 2.18 Check MDE Sense operational event log

Purpose: Review recent MDE sensor events on one device.

```kql
WindowsEvent('Microsoft-Windows-SENSE/Operational', 1d)
| project LoggedDateTime, EventId, Level, ProviderName, Message
| order by LoggedDateTime desc
| take 50
```

---

## 2.19 Check application crashes during pilot

Purpose: Identify application crashes that may occur after Trellix removal or Defender policy application.

```kql
WindowsAppCrashEvent
| project LoggedDateTime, AppName, AppVersion, AppPath, WindowsUserAccount
| order by LoggedDateTime desc
| take 50
```

---

## 2.20 Check top CPU-consuming processes on one device

Purpose: Troubleshoot performance complaints during pilot rollout.

```kql
Process
| project ProcessName, ProcessId, Path, ProcessorTimePercent, WorkingSetSizeBytes, WindowsUserAccount, StartDateTime
| order by ProcessorTimePercent desc
| take 20
```

---

## 2.21 Check memory-heavy processes on one device

Purpose: Troubleshoot performance complaints after Defender activation.

```kql
Process
| project ProcessName, ProcessId, Path, WorkingSetSizeBytes, WindowsUserAccount, StartDateTime
| order by WorkingSetSizeBytes desc
| take 20
```

---

# 3. Recommended per-device migration checklist

Use the following checks before and after Trellix removal.

## 3.1 Before Trellix removal

Expected state:

| Check | Expected result |
|---|---|
| MDE Sense service | `Sense` exists and is running |
| Defender AV service | `WinDefend` exists and is running |
| Trellix/McAfee services | Present and likely running |
| Defender AV mode | Usually passive mode while Trellix is active; validate with PowerShell or Defender portal |
| ASR policy | Audit mode only |
| Intune policies | Assigned and successfully applied |

Suggested single-device queries:

```kql
WindowsService
| where ServiceName == "Sense" or ServiceName == "WinDefend" or DisplayName contains "Trellix" or DisplayName contains "McAfee" or ServiceName contains "mfe" or ServiceName contains "masvc"
| project ServiceName, DisplayName, State, StartMode, ProcessId, Path
| order by ServiceName asc
```

```kql
WindowsRegistry('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules')
| project RegistryKey, ValueName, ValueType, ValueData
| order by ValueName asc
```

---

## 3.2 After Trellix removal

Expected state:

| Check | Expected result |
|---|---|
| Trellix/McAfee services | No longer present or not running |
| Trellix/McAfee processes | No longer running |
| Defender AV service | `WinDefend` running |
| MDE Sense service | `Sense` running |
| Defender AV mode | Active/normal mode; validate with PowerShell or Defender portal |
| Real-time protection | Enabled; validate with PowerShell, Defender portal, or policy state |
| ASR policy | Audit mode only |

Suggested single-device queries:

```kql
WindowsService
| where ServiceName == "Sense" or ServiceName == "WinDefend" or ServiceName == "WdNisSvc" or DisplayName contains "Trellix" or DisplayName contains "McAfee" or ServiceName contains "mfe" or ServiceName contains "masvc"
| project ServiceName, DisplayName, State, StartMode, ProcessId, Path
| order by ServiceName asc
```

```kql
Process
| where ProcessName contains "mfe" or ProcessName contains "mcshield" or ProcessName contains "masvc" or ProcessName contains "macmn" or ProcessName contains "Trellix" or ProcessName contains "McAfee" or ProcessName contains "MsMpEng" or ProcessName contains "Sense"
| project ProcessName, ProcessId, Path, CommandLine, WindowsUserAccount, StartDateTime
| order by ProcessName asc
```

---

# 4. Complementary PowerShell checks

Some Defender AV states are usually easier and clearer to validate with PowerShell on the device, through a remediation script, or via another management channel.

## 4.1 Defender AV state

```powershell
Get-MpComputerStatus | Select-Object `
    AMRunningMode,
    RealTimeProtectionEnabled,
    AntivirusEnabled,
    AMServiceEnabled,
    AntispywareEnabled,
    BehaviorMonitorEnabled,
    IoavProtectionEnabled,
    NISEnabled,
    IsTamperProtected,
    DefenderSignaturesOutOfDate,
    AntivirusSignatureLastUpdated
```

Expected during coexistence with Trellix active:

```text
AMRunningMode             : Passive Mode
RealTimeProtectionEnabled : False
AntivirusEnabled          : True
AMServiceEnabled          : True
```

Expected after Trellix removal:

```text
AMRunningMode             : Normal
RealTimeProtectionEnabled : True
AntivirusEnabled          : True
AMServiceEnabled          : True
```

---

## 4.2 Registered antivirus provider

```powershell
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
    Select-Object displayName, productState, pathToSignedProductExe, pathToSignedReportingExe
```

Use this to confirm whether Trellix/McAfee or Microsoft Defender Antivirus is registered as active AV provider.

---

## 4.3 MDE Sense service

```powershell
Get-Service Sense | Select-Object Name, DisplayName, Status, StartType
```

---

## 4.4 Defender and Trellix services

```powershell
Get-Service |
    Where-Object {
        $_.Name -in @('Sense','WinDefend','WdNisSvc','mpssvc') -or
        $_.Name -like '*mfe*' -or
        $_.Name -like '*masvc*' -or
        $_.DisplayName -like '*Trellix*' -or
        $_.DisplayName -like '*McAfee*'
    } |
    Select-Object Name, DisplayName, Status, StartType
```

---

# 5. Recommended rollout usage

Use the queries in this order during each rollout wave:

| Phase | Query/check focus |
|---|---|
| Before wave | Fleet OS version, disk space, TPM, BitLocker, Windows updates |
| Before Trellix removal | Sense service, WinDefend service, Trellix services/processes, ASR audit registry |
| Immediately after Trellix removal | Trellix services/processes absent, WinDefend running, Sense running |
| After reboot/check-in | Defender AV active mode, real-time protection enabled, Intune policy success |
| During monitoring | Defender operational events, Sense operational events, app crashes, top CPU/memory processes |

---

# 6. Portal locations

| Task | Portal location |
|---|---|
| Multiple-device query | `Intune admin center` -> `Devices` -> `Device query` |
| Single-device query | `Intune admin center` -> `Devices` -> `Windows` -> select device -> `Device query` |
| MDE onboarding policy | `Intune admin center` -> `Endpoint security` -> `Endpoint detection and response` |
| Defender Antivirus policy | `Intune admin center` -> `Endpoint security` -> `Antivirus` |
| ASR policy | `Intune admin center` -> `Endpoint security` -> `Attack surface reduction` |
| Device inventory in Defender | `Microsoft Defender portal` -> `Assets` -> `Devices` |
| Advanced Hunting | `Microsoft Defender portal` -> `Hunting` -> `Advanced hunting` |

---

# 7. References

- Microsoft Intune Device query: <https://learn.microsoft.com/en-us/intune/advanced-analytics/device-query>
- Microsoft Intune Device query for multiple devices: <https://learn.microsoft.com/en-us/intune/advanced-analytics/device-query-multiple-devices>
- Intune Data Platform schema: <https://learn.microsoft.com/en-us/intune/advanced-analytics/ref-data-platform-schema>
- Monitor Microsoft Defender for Endpoint with Intune: <https://learn.microsoft.com/en-us/intune/device-security/microsoft-defender/monitor>
- Configure Microsoft Defender Antivirus with Intune: <https://learn.microsoft.com/en-us/defender-endpoint/use-intune-config-manager-microsoft-defender-antivirus>

---

# 8. Notes for this migration project

- ASR rules should be set to **audit mode** only during the AV migration rollout unless enforcement is explicitly approved as a separate hardening scope.
- Trellix/McAfee removal should be controlled by dedicated rollout groups, not broad assignments.
- Defender Antivirus normally becomes active only after the third-party AV is removed, disabled, or no longer registered as active AV provider.
- Keep rollout groups, Trellix uninstall assignments, Defender AV policy assignments, and ASR audit assignments logically separated for better rollback and troubleshooting.
