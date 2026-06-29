# Session 2 - Übung 4
## Device Timeline zu einem verdächtigen Prozess lesen

## Praxissituation

Ein Benutzer meldet dem Service Desk, dass nach dem Öffnen eines Word-Dokuments kurz ein schwarzes Fenster aufgeblitzt ist. Kurz darauf erzeugt Microsoft Defender for Endpoint einen Alert auf dem Gerät. Die IT muss nun nachvollziehen, ob Word tatsächlich PowerShell, cmd.exe oder ein Skript gestartet hat.

Diese Situation ist im Betriebsalltag relevant, weil Office-Dokumente häufig als Einstiegspunkt für Angriffe genutzt werden. Besonders verdächtig sind Prozessketten wie `winword.exe -> powershell.exe`, `excel.exe -> cmd.exe` oder `outlook.exe -> wscript.exe`.

## Ziel der Übung

Die Teilnehmer sollen die Device Timeline im Microsoft Defender Portal verwenden, um vor und nach einem Alert relevante Prozess-, Datei- und Netzwerkereignisse zu finden.

## Benötigte Berechtigungen

- Zugriff auf Microsoft Defender Portal
- Leserechte auf Geräteinformationen und Device Timeline
- Ein geeignetes Testgerät oder ein ungefährlicher Beispielalert

## Ausgangspunkt

Portal:

```text
https://security.microsoft.com
```

Typische Pfade:

```text
Assets -> Devices -> <Gerät> -> Timeline
```

oder aus einem Alert heraus:

```text
Incident / Alert -> Device -> Timeline
```

## Aufgabe

Untersuche ein Gerät mit einem verdächtigen Alert oder einem vorbereiteten Beispiel und beantworte:

- Welcher Prozess hat die verdächtige Aktivität ausgelöst?
- Gab es eine Office-Anwendung als Ursprung?
- Welche Folgeprozesse wurden gestartet?
- Gab es Netzwerkverbindungen oder Dateiaktivitäten?
- Ist das Verhalten legitim, verdächtig oder unklar?

## Schritt-für-Schritt-Anleitung

### 1. Gerät öffnen

1. Öffne das Microsoft Defender Portal.
2. Suche das betroffene Gerät über:

   ```text
   Assets -> Devices
   ```

3. Öffne die Device Page.
4. Wechsle zur `Timeline`.

### 2. Zeitraum eingrenzen

Grenze die Timeline auf den Zeitraum des Alerts ein.

| Prüffeld | Beobachtung |
|---|---|
| Zeitpunkt des Alerts |  |
| Betrachteter Zeitraum davor | z. B. 15 Minuten |
| Betrachteter Zeitraum danach | z. B. 30 Minuten |

### 3. Filter verwenden

Nutze Filter, um relevante Ereignisse schneller zu finden:

| Filter | Zweck |
|---|---|
| Process events | Prozessstarts erkennen |
| File events | Dateien und Pfade prüfen |
| Network events | Verbindungen zu externen Zielen prüfen |
| Alert events | Kontext zum Alert finden |

### 4. Prozesskette suchen

Suche nach verdächtigen Prozessketten.

Typische Beispiele:

```text
winword.exe -> powershell.exe
excel.exe -> cmd.exe
outlook.exe -> wscript.exe
powerpnt.exe -> mshta.exe
```

Dokumentiere die beobachtete Kette:

| Ebene | Prozess | Pfad / Command Line | Bewertung |
|---:|---|---|---|
| Parent |  |  |  |
| Child |  |  |  |
| Folgeprozess |  |  |  |

### 5. Command Line prüfen

Wenn sichtbar, prüfe die Command Line.

Verdächtige Hinweise können sein:

| Hinweis | Warum relevant? |
|---|---|
| `-EncodedCommand` | Häufig bei verschleierter PowerShell |
| `DownloadString` | Kann auf Nachladen von Code hinweisen |
| `Invoke-WebRequest` | Download aus dem Internet möglich |
| `%TEMP%` oder `%APPDATA%` | Häufige Ablageorte für Malware |
| Base64-ähnliche lange Strings | Mögliche Obfuskation |

### 6. Netzwerk- und Dateiaktivitäten prüfen

Dokumentiere relevante Ereignisse:

| Typ | Beobachtung | Bewertung |
|---|---|---|
| Datei erstellt |  |  |
| Datei ausgeführt |  |  |
| Netzwerkverbindung |  |  |
| URL / IP |  |  |
| Weitere Alerts |  |  |

## Optionale Advanced-Hunting-Abfrage

Wenn ein Gerätename bekannt ist:

```kql
let DeviceToCheck = "DEVICE-NAME-HERE";
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName =~ DeviceToCheck
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

Allgemeine Suche nach Office-Prozessen, die PowerShell oder cmd starten:

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Erwartetes Ergebnis

Die Teilnehmer sollen eine kurze technische Bewertung erstellen können:

| Frage | Antwort |
|---|---|
| Welcher Prozess war Ursprung? |  |
| Welcher Prozess wurde gestartet? |  |
| War die Prozesskette ungewöhnlich? |  |
| Gab es Download- oder Netzwerkaktivität? |  |
| Gab es weitere Alerts? |  |
| Ist Eskalation nötig? |  |

## Bewertung im Betriebsalltag

| Beobachtung | Mögliche Bewertung |
|---|---|
| Word startet PowerShell mit EncodedCommand | Hoch verdächtig |
| Excel startet internes signiertes Add-in | Kontext prüfen, ggf. legitim |
| Outlook startet Browser | Kann legitim sein, aber URL prüfen |
| Script startet EXE aus TEMP | Verdächtig |
| Keine Folgeaktivität nach Blockierung | Schutzmaßnahme vermutlich erfolgreich |

## Diskussionsfragen

- Welche Prozessketten wären im Unternehmen normal?
- Welche Office-Automatisierungen gibt es?
- Wann muss der Fachbereich eingebunden werden?
- Wann sollte ein MSSP/SOC übernehmen?
- Welche Informationen gehören in ein Ticket?

## Merksatz

Die Device Timeline hilft zu verstehen, was wirklich passiert ist. Gerade Prozessketten wie Office -> PowerShell sind häufig wichtiger als der einzelne Alert-Name.


---
---

# POWERSHELL

---

### 1. Aktuell laufende Office- und Script-Prozesse anzeigen

```powershell
Get-Process |
    Where-Object {
        $_.ProcessName -match "winword|excel|powerpnt|outlook|powershell|pwsh|cmd|wscript|cscript|mshta"
    } |
    Select-Object ProcessName, Id, StartTime, Path |
    Sort-Object StartTime
```

---

### 2. Prozessdetails über CIM abfragen

```powershell
Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -match "WINWORD.EXE|EXCEL.EXE|POWERPNT.EXE|OUTLOOK.EXE|powershell.exe|pwsh.exe|cmd.exe|wscript.exe|cscript.exe|mshta.exe"
    } |
    Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath |
    Format-List
```

---

### 3. Parent-Prozess zu einem Prozess finden

```powershell
$ProcessId = 1234

$process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId"
$parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($process.ParentProcessId)"

[PSCustomObject]@{
    ProcessName = $process.Name
    ProcessId = $process.ProcessId
    CommandLine = $process.CommandLine
    ParentProcessName = $parent.Name
    ParentProcessId = $parent.ProcessId
    ParentCommandLine = $parent.CommandLine
} | Format-List
```

---

### 4. Verdächtige Prozessnamen suchen

```powershell
$SuspiciousProcessNames = @(
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe"
)

Get-CimInstance Win32_Process |
    Where-Object { $SuspiciousProcessNames -contains $_.Name.ToLower() } |
    Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath |
    Format-List
```

---

### 5. PowerShell Script Block Logging prüfen

Wenn Script Block Logging aktiviert ist, können PowerShell-Inhalte im Event Log sichtbar sein.

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 |
    Select-Object TimeCreated, Id, Message |
    Format-List
```

---

### 6. Defender-ASR-Events im Zeitraum prüfen

```powershell
$StartTime = (Get-Date).AddHours(-6)

Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    Id = 1121,1122
    StartTime = $StartTime
} |
Select-Object TimeCreated, Id, Message |
Format-List
```