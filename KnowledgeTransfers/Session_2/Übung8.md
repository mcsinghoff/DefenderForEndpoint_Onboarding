# Session 2 - Übung 8
## Einfache Advanced-Hunting-Abfrage für ASR-Events nutzen

## Praxissituation

Nach der Einführung von ASR im Audit Mode fragt die IT-Leitung: "Welche Geräte hatten in den letzten 7 Tagen ASR-Ereignisse, und welche Regeln waren am häufigsten betroffen?" Eine manuelle Prüfung einzelner Geräte reicht dafür nicht aus.

Im Betriebsalltag nach der MDE-Migration wird Advanced Hunting hilfreich, wenn man Fragen beantworten muss, die über einzelne Portalansichten hinausgehen.

## Ziel der Übung

Die Teilnehmer sollen eine einfache KQL-Abfrage in Advanced Hunting ausführen, ASR-Ereignisse finden und die Ergebnisse nach Gerät, Regel oder Prozess zusammenfassen.

## Benötigte Berechtigungen

- Zugriff auf Microsoft Defender Portal
- Zugriff auf Advanced Hunting
- Leserechte auf Endpoint-Telemetrie

## Ausgangspunkt

Portal:

```text
https://security.microsoft.com
```

Typischer Pfad:

```text
Hunting -> Advanced hunting
```

## Aufgabe

Erstelle eine Abfrage, die ASR-Ereignisse der letzten 7 Tage zeigt und beantworte:

- Welche Geräte hatten ASR-Ereignisse?
- Welche ASR-Aktionen wurden ausgelöst?
- Welche Prozesse waren beteiligt?
- Gibt es Häufungen auf bestimmten Geräten oder Anwendungen?

## KQL-Grundlagen für diese Übung

| Element | Bedeutung |
|---|---|
| `DeviceEvents` | Tabelle für viele Geräteereignisse, darunter häufig ASR-Ereignisse |
| `where` | Filtert Zeilen |
| `project` | Wählt Spalten aus |
| `summarize` | Aggregiert Ergebnisse |
| `order by` | Sortiert Ergebnisse |
| `ago(7d)` | Zeitraum der letzten 7 Tage |

## Schritt-für-Schritt-Anleitung

### 1. Advanced Hunting öffnen

1. Öffne das Microsoft Defender Portal.
2. Navigiere zu:

   ```text
   Hunting -> Advanced hunting
   ```

3. Erstelle eine neue Query.

### 2. Erste ASR-Suche ausführen

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Asr"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, AccountName
| order by Timestamp desc
```

### 3. Ergebnisse interpretieren

| Spalte | Bedeutung |
|---|---|
| `Timestamp` | Zeitpunkt des Ereignisses |
| `DeviceName` | Betroffenes Gerät |
| `ActionType` | Art des ASR-Ereignisses |
| `InitiatingProcessFileName` | Prozess, der die Aktion ausgelöst hat |
| `InitiatingProcessCommandLine` | Command Line des auslösenden Prozesses |
| `FileName` | Betroffene Datei, falls vorhanden |
| `FolderPath` | Pfad der betroffenen Datei, falls vorhanden |
| `AccountName` | Beteiligter Benutzer, falls vorhanden |

### 4. Ereignisse nach Aktion zusammenfassen

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Asr"
| summarize EventCount=count() by ActionType
| order by EventCount desc
```

### 5. Ereignisse nach Gerät zusammenfassen

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Asr"
| summarize EventCount=count() by DeviceName
| order by EventCount desc
```

### 6. Ereignisse nach Prozess zusammenfassen

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Asr"
| summarize EventCount=count() by InitiatingProcessFileName, FileName
| order by EventCount desc
```

### 7. Ergebnisse dokumentieren

| Frage | Antwort |
|---|---|
| Wie viele ASR-Events gab es? |  |
| Welche ActionType war am häufigsten? |  |
| Welches Gerät hatte die meisten Events? |  |
| Welcher Prozess war am häufigsten beteiligt? |  |
| Gibt es Kandidaten für False Positive? |  |
| Gibt es Kandidaten für Block Mode? |  |

## Erweiterung: Office-Prozessketten suchen

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Erweiterung: Ergebnisse für einen bestimmten Client filtern

```kql
let DeviceToCheck = "DEVICE-NAME-HERE";
DeviceEvents
| where Timestamp > ago(30d)
| where DeviceName =~ DeviceToCheck
| where ActionType startswith "Asr"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, AccountName
| order by Timestamp desc
```

## Wenn keine Ergebnisse erscheinen

| Mögliche Ursache | Prüfung |
|---|---|
| Zeitraum zu kurz | `ago(30d)` statt `ago(7d)` testen |
| Keine ASR-Events im Tenant | ASR-Report prüfen |
| ASR-Policy nicht zugewiesen | Intune Assignment prüfen |
| Defender AV noch Passive Mode | Active Mode nach McAfee-Removal prüfen |
| Andere ActionType-Namen | `where ActionType contains "Asr"` testen |
| Rechte fehlen | Advanced-Hunting-Berechtigungen prüfen |

Alternative Suche:

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType contains "Asr"
| take 100
```

## Erwartetes Ergebnis

Die Teilnehmer sollen eine einfache Auswertung erstellen können:

| Ergebnisbereich | Beispiel |
|---|---|
| Top ASR Actions | Welche Regeln lösen am häufigsten aus? |
| Top Geräte | Welche Geräte sind besonders betroffen? |
| Top Prozesse | Welche Anwendungen verursachen Events? |
| Bewertung | Block-Kandidat, False-Positive-Kandidat oder weitere Analyse |

## Bewertung im Betriebsalltag

| Beobachtung | Mögliche Aktion |
|---|---|
| Viele Events von derselben Fachanwendung | App-Owner-Review starten |
| Viele Events von Office -> PowerShell | Security-relevant untersuchen |
| Events auf nur einem Gerät | Gerät gezielt untersuchen |
| Events auf vielen Geräten | Regel oder Anwendung breit prüfen |
| Keine Events nach Pilot | Pilotgruppe, Zeitraum und Policy-Anwendung prüfen |

## Diskussionsfragen

- Welche ASR-Regel löst im Pilot am häufigsten aus?
- Welche Geräte sind auffällig?
- Welche Prozesse erzeugen die meisten Events?
- Welche Events wirken legitim?
- Welche Events sollten dem MSSP/SOC gezeigt werden?
- Welche Regel könnte in die nächste Pilotstufe gehen?

## Merksatz

Advanced Hunting beantwortet Betriebsfragen, die im Portal nicht immer direkt sichtbar sind. Für ASR ist es besonders nützlich, um Pilotdaten nach Regel, Gerät und Prozess zusammenzufassen.



---
---

# POWERSHELL

---

### 1. Gerätename lokal prüfen

```powershell
$env:COMPUTERNAME
```

---

### 2. Angemeldeten Benutzer prüfen

```powershell
whoami
```

Oder ausführlicher:

```powershell
Get-CimInstance Win32_ComputerSystem |
    Select-Object UserName, Domain, Manufacturer, Model
```

---

### 3. Defender-Status für Hunting-Kontext prüfen

```powershell
Get-MpComputerStatus | Select-Object `
    AMRunningMode,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    AMServiceEnabled,
    IsTamperProtected,
    AntivirusSignatureLastUpdated
```

---

### 4. ASR-Konfiguration lokal exportieren

```powershell
$OutputPath = "$env:TEMP\asr-local-status.csv"

$pref = Get-MpPreference

$asr = for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
    [PSCustomObject]@{
        DeviceName = $env:COMPUTERNAME
        RuleId = $pref.AttackSurfaceReductionRules_Ids[$i]
        Action = $pref.AttackSurfaceReductionRules_Actions[$i]
    }
}

$asr | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$OutputPath
```

---

### 5. ASR-Ereignisse lokal exportieren

```powershell
$OutputPath = "$env:TEMP\asr-local-events.csv"
$StartTime = (Get-Date).AddDays(-30)

$events = Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    Id = 1121,1122
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

$events |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$OutputPath
```

---

### 6. Lokale Daten für einen auffälligen Prozess sammeln

```powershell
$ProcessName = "msedgewebview2"

Get-CimInstance Win32_Process |
    Where-Object { $_.Name -like "$ProcessName*" } |
    Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath |
    Format-List
```

---

### 7. Hashes für betroffene Datei sammeln

```powershell
$FilePath = "C:\Path\To\File.exe"

Get-FileHash -Path $FilePath -Algorithm SHA256
Get-AuthenticodeSignature -FilePath $FilePath
```

---

### 8. Passende Advanced-Hunting-Query zum Vergleich

Diese Query wird nicht in PowerShell ausgeführt, sondern im Defender Portal unter Advanced Hunting.

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType has "Asr"
| summarize
    Count=count(),
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    Devices=dcount(DeviceName),
    Users=dcount(AccountName)
    by ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Count desc
```