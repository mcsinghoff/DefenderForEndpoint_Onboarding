## Übung 6: Sense-Service und Defender AV Service prüfen

### Ziel

Wir wollen den Unterschied zwischen dem MDE/EDR-Sensor und Defender Antivirus verstehen.

#### Tipp: Da der MDE bereits im Passive Mode auf allen Geräten verteilt ist, kannst du diese Funktion wahrscheinlich auch auf deinem - nicht migrierten - Gerät testen. 

### PowerShell
```powershell
Get-Service -Name Sense, WinDefend
```
oder:
```powershell
Get-Service -Name Sense, WinDefend | Select-Object Name, DisplayName, Status, StartType
```

### Interpretation

| Service | Bedeutung |
|---|---|
| `Sense` | Microsoft Defender for Endpoint Sensor / EDR-Komponente |
| `WinDefend` | Microsoft Defender Antivirus Service |

### Merksatz

Der `Sense`-Service ist für MDE-Onboarding, EDR-Telemetrie und Sichtbarkeit im Defender-Portal relevant.  
Der `WinDefend`-Service ist der lokale Microsoft Defender Antivirus Service.

Ein Gerät kann einen laufenden `Sense`-Service haben, während Defender Antivirus wegen McAfee/Trellix noch im Passive Mode ist.