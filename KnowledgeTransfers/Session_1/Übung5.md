## Übung 5: Defender Antivirus Status lokal prüfen

### Ziel

Wir wollen den lokalen Defender-Zustand auf einem Windows-11-Client interpretieren können.

### PowerShell

```powershell
Get-MpComputerStatus | Select-Object `
    AMRunningMode,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    AMServiceEnabled,
    IsTamperProtected,
    AntivirusSignatureVersion,
    AntivirusSignatureLastUpdated,
    NISEnabled,
    NISSignatureLastUpdated
```

### Interpretation

| Feld | Bedeutung |
|---|---|
| `AMRunningMode` | Zeigt, ob Defender AV im Passive Mode oder Active/Normal Mode läuft |
| `AntivirusEnabled` | Gibt an, ob Defender Antivirus grundsätzlich aktiviert ist |
| `RealTimeProtectionEnabled` | Gibt an, ob Echtzeitschutz aktiv ist |
| `AMServiceEnabled` | Gibt an, ob der Defender AV-Dienst aktiv ist |
| `IsTamperProtected` | Gibt an, ob Manipulationsschutz aktiv ist |
| `AntivirusSignatureVersion` | Version der Defender Antivirus-Signaturen |
| `AntivirusSignatureLastUpdated` | Zeitpunkt der letzten Defender-Signaturaktualisierung |
| `NISEnabled` | Status des Network Inspection System |
| `NISSignatureLastUpdated` | Zeitpunkt der letzten NIS-Signaturaktualisierung |

### Erwartete Zustände

| Migrationsphase | Erwarteter Zustand |
|---|---|
| McAfee/Trellix noch aktiv | `AMRunningMode = Passive Mode`, `RealTimeProtectionEnabled` häufig `False` |
| McAfee/Trellix entfernt | `AMRunningMode = Normal`, `RealTimeProtectionEnabled = True` |
| Defender AV aktiv | `AntivirusEnabled = True`, `AMServiceEnabled = True` |
| Signaturen aktuell | `AntivirusSignatureLastUpdated` ist aktuell |
