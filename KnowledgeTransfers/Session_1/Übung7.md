## Übung 7: PowerShell-Hilfe für Defender-Cmdlets nutzen

### Ziel

Wir wollen lernen, wie sie Defender-PowerShell-Cmdlets selbst nachschlagen und Parameter verstehen können.

### Aufgabe 1: Defender-Cmdlets finden

```powershell
Get-Command -Module Defender
```

### Aufgabe 2: Hilfe zu einem Cmdlet anzeigen

```powershell
Get-Help Get-MpComputerStatus
```

### Aufgabe 3: Beispiele anzeigen

```powershell
Get-Help Get-MpComputerStatus -Examples
```

### Aufgabe 4: Online-Hilfe öffnen

```powershell
Get-Help Get-MpPreference -Online
```

### Aufgabe 5: Einen bestimmten Parameter nachschlagen

```powershell
Get-Help Set-MpPreference -Parameter DisableRealtimeMonitoring
```

### Diskussionsfragen

- Welches Cmdlet zeigt den aktuellen Defender-Zustand?
- Welches Cmdlet zeigt Defender-Konfigurationen?
- Welches Cmdlet würde Einstellungen ändern?
- Warum sollten produktive Änderungen nicht manuell per PowerShell, sondern über Intune erfolgen?
