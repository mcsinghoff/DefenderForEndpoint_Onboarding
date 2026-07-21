<#
.SYNOPSIS
    Checks Microsoft Defender Antivirus active mode on pilot devices.

.DESCRIPTION
    Queries a predefined list of pilot devices via PowerShell remoting and checks
    whether Microsoft Defender Antivirus is active after Trellix/McAfee removal.

    The script reports AMRunningMode, real-time protection, Defender service state,
    MDE Sense service state, signature status, and whether Trellix/McAfee is still
    registered as an antivirus product in Windows Security Center.

    AMRunningMode = Normal means Microsoft Defender Antivirus is active.
    AMRunningMode = Passive Mode usually means another antivirus product is still
    installed or registered as active.

.PARAMETER OutputPath
    Optional CSV output path. If omitted, no CSV file is written.

.PARAMETER Credential
    Optional credential for PowerShell remoting. If omitted, the current user context is used.

.PARAMETER ThrottleLimit
    Number of devices queried in parallel by Invoke-Command.

.EXAMPLE
    .\Get-AMRunningModeFromDeviceList.ps1

.EXAMPLE
    .\Get-AMRunningModeFromDeviceList.ps1 -OutputPath "C:\Temp\PilotDefenderAvState.csv"

.EXAMPLE
    .\Get-AMRunningModeFromDeviceList.ps1 -OutputPath "C:\Temp\PilotDefenderAvState.csv" -Credential (Get-Credential)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [int]$ThrottleLimit = 16
)

$PilotDevices = @(
    "TMPWIN10", "W10NB1483", "W10NB1800", "W10NB21022", "W10NB320", "W10NB983", "W10NUC001", "W10PC015",
    "W10PC1000", "W10PC1457", "W10PC1927", "W10PC2000", "W10PC5000", "W10PC5001", "W10PC5002", "W10PC8001",
    "W10PC8003XT", "W10TAB22110", "W11NB1815", "W11NB22052", "W11NB22055", "W11NB22081", "W11NB23036", "W11NB23047",
    "W11NB23083", "W11NB23086", "W11NB24008", "W11NB24011", "W11NB24032", "W11NB24048", "W11NB24078", "W11NB24130",
    "W11NB24131", "W11NB25000", "W11NB25066", "W11NB25067", "W11NB25089", "W11NB25151", "W11NB25170", "W11NB25250",
    "W11NB26019", "W11NB850", "W11NB8888", "W11NBBI02", "W11NBBI06", "W11NBBI07", "W11NBBI08", "W11NBBI09",
    "W11NBBI10", "W11NBBI23", "W11NBTESTNP", "W11PC1746", "W11PC1787", "W11PC1847", "W11PC1883", "W11PC1906",
    "W11PC24099", "W11PC25109", "W11PC25110", "W11PC6000", "W11PC9601", "W11PC9603", "W11PC9610"
)

$RemoteScriptBlock = {
    $ErrorActionPreference = "Stop"

    try {
        $mp = Get-MpComputerStatus

        $avProducts = Get-CimInstance `
            -Namespace root/SecurityCenter2 `
            -ClassName AntiVirusProduct `
            -ErrorAction SilentlyContinue

        $trellixProducts = @(
            $avProducts | Where-Object {
                $_.displayName -match "McAfee|Trellix"
            } | Select-Object -ExpandProperty displayName
        )

        $winDefend = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        $sense     = Get-Service -Name Sense -ErrorAction SilentlyContinue
        $mdCore    = Get-Service -Name MDCoreSvc -ErrorAction SilentlyContinue

        $defenderAvActive =
            ([string]$mp.AMRunningMode -eq "Normal") -and
            ($mp.AntivirusEnabled -eq $true) -and
            ($mp.RealTimeProtectionEnabled -eq $true) -and
            ($mp.AMServiceEnabled -eq $true)

        $migrationState = if ($defenderAvActive -and $trellixProducts.Count -eq 0) {
            "Success"
        }
        elseif ([string]$mp.AMRunningMode -eq "Passive Mode") {
            "Review - Defender passive"
        }
        elseif ($trellixProducts.Count -gt 0) {
            "Review - Trellix/McAfee registered"
        }
        else {
            "Review"
        }

        [PSCustomObject]@{
            DeviceName                    = $env:COMPUTERNAME
            QueryStatus                   = "Success"
            MigrationState                = $migrationState
            DefenderAvActive              = $defenderAvActive
            AMRunningMode                 = [string]$mp.AMRunningMode
            AntivirusEnabled              = $mp.AntivirusEnabled
            RealTimeProtectionEnabled     = $mp.RealTimeProtectionEnabled
            AMServiceEnabled              = $mp.AMServiceEnabled
            BehaviorMonitorEnabled        = $mp.BehaviorMonitorEnabled
            IoavProtectionEnabled         = $mp.IoavProtectionEnabled
            OnAccessProtectionEnabled     = $mp.OnAccessProtectionEnabled
            IsTamperProtected             = $mp.IsTamperProtected
            SignatureLastUpdated          = $mp.AntivirusSignatureLastUpdated
            SignatureVersion              = $mp.AntivirusSignatureVersion
            WinDefendStatus               = if ($winDefend) { $winDefend.Status.ToString() } else { "NotFound" }
            SenseStatus                   = if ($sense) { $sense.Status.ToString() } else { "NotFound" }
            MDCoreSvcStatus               = if ($mdCore) { $mdCore.Status.ToString() } else { "NotFound" }
            TrellixOrMcAfeeRegistered     = ($trellixProducts.Count -gt 0)
            TrellixOrMcAfeeProducts       = ($trellixProducts -join "; ")
            ErrorMessage                  = $null
        }
    }
    catch {
        [PSCustomObject]@{
            DeviceName                    = $env:COMPUTERNAME
            QueryStatus                   = "Query failed"
            MigrationState                = "Failed - local query error"
            DefenderAvActive              = $false
            AMRunningMode                 = $null
            AntivirusEnabled              = $null
            RealTimeProtectionEnabled     = $null
            AMServiceEnabled              = $null
            BehaviorMonitorEnabled        = $null
            IoavProtectionEnabled         = $null
            OnAccessProtectionEnabled     = $null
            IsTamperProtected             = $null
            SignatureLastUpdated          = $null
            SignatureVersion              = $null
            WinDefendStatus               = $null
            SenseStatus                   = $null
            MDCoreSvcStatus               = $null
            TrellixOrMcAfeeRegistered     = $null
            TrellixOrMcAfeeProducts       = $null
            ErrorMessage                  = $_.Exception.Message
        }
    }
}

$invokeParams = @{
    ComputerName  = $PilotDevices
    ScriptBlock   = $RemoteScriptBlock
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = "SilentlyContinue"
    ErrorVariable = "RemoteErrors"
}

if ($Credential) {
    $invokeParams.Credential = $Credential
}

Write-Host "Querying $($PilotDevices.Count) pilot devices..." -ForegroundColor Cyan

$results = @(Invoke-Command @invokeParams)

$respondedDevices = @(
    $results |
    Where-Object { $_.PSComputerName } |
    Select-Object -ExpandProperty PSComputerName -Unique
)

$missingResults = foreach ($device in $PilotDevices) {
    if ($respondedDevices -notcontains $device) {
        [PSCustomObject]@{
            DeviceName                    = $device
            QueryStatus                   = "Connection failed"
            MigrationState                = "Failed - no remote result"
            DefenderAvActive              = $false
            AMRunningMode                 = $null
            AntivirusEnabled              = $null
            RealTimeProtectionEnabled     = $null
            AMServiceEnabled              = $null
            BehaviorMonitorEnabled        = $null
            IoavProtectionEnabled         = $null
            OnAccessProtectionEnabled     = $null
            IsTamperProtected             = $null
            SignatureLastUpdated          = $null
            SignatureVersion              = $null
            WinDefendStatus               = $null
            SenseStatus                   = $null
            MDCoreSvcStatus               = $null
            TrellixOrMcAfeeRegistered     = $null
            TrellixOrMcAfeeProducts       = $null
            ErrorMessage                  = "Device did not return a PowerShell remoting result."
        }
    }
}

$finalResults = @(
    $results | Select-Object `
        DeviceName,
        QueryStatus,
        MigrationState,
        DefenderAvActive,
        AMRunningMode,
        AntivirusEnabled,
        RealTimeProtectionEnabled,
        AMServiceEnabled,
        BehaviorMonitorEnabled,
        IoavProtectionEnabled,
        OnAccessProtectionEnabled,
        IsTamperProtected,
        SignatureLastUpdated,
        SignatureVersion,
        WinDefendStatus,
        SenseStatus,
        MDCoreSvcStatus,
        TrellixOrMcAfeeRegistered,
        TrellixOrMcAfeeProducts,
        ErrorMessage

    $missingResults
) | Sort-Object DeviceName

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan

$finalResults |
    Group-Object MigrationState |
    Sort-Object Name |
    Select-Object Name, Count |
    Format-Table -AutoSize

Write-Host ""
Write-Host "Device status:" -ForegroundColor Cyan

$finalResults |
    Select-Object `
        DeviceName,
        MigrationState,
        DefenderAvActive,
        AMRunningMode,
        RealTimeProtectionEnabled,
        WinDefendStatus,
        SenseStatus,
        TrellixOrMcAfeeRegistered,
        SignatureLastUpdated |
    Format-Table -AutoSize

if ($OutputPath) {
    $outputDirectory = Split-Path -Path $OutputPath -Parent

    if ($outputDirectory -and -not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    $finalResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "CSV exported to: $OutputPath" -ForegroundColor Green
}