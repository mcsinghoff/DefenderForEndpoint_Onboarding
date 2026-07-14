# Session 3 - Übung 2
## Incident Investigation (Untersuchung) mit Evidence (Beweise), Entities (Entitäten) und Device Timeline (Gerätezeitachse)

## Praxissituation

Das MSSP meldet einen Incident mit dem Hinweis: `Suspicious (Verdächtig) PowerShell activity on a Windows 11 device`. Das MSSP benötigt von der internen IT Informationen zum Benutzer, zur Gerätekritikalität und dazu, ob die Prozesskette zu einem legitimen Administrations- oder Softwareverteilungsprozess gehört.

## Ziel der Übung

Die Teilnehmer sollen einen Incident technisch und betrieblich untersuchen und aus Alerts (Warnungen), Evidence (Beweise), Entities (Entitäten), Device Page (Geräteseite) und Timeline (Zeitachse) eine nachvollziehbare Angriffsgeschichte erstellen.

## Benötigte Berechtigungen

- Leserechte auf Incidents, Alerts (Warnungen), Evidence (Beweise) und Devices (Geräte)
- Leserechte auf Device Timeline (Gerätezeitachse)
- Optional Advanced Hunting (Erweiterte Suche)
- Kein Ausführen produktiver Response Actions (Antwortaktionen)

## Aufgabe

Untersuche einen geeigneten Beispiel-Incident und beantworte:

- Welcher Prozess war der Ursprung?
- Welche Datei oder Command Line (Befehlszeile) ist relevant?
- Welcher Benutzer war beteiligt?
- Gibt es weitere Geräte oder Alerts (Warnungen)?
- Welche Evidence (Beweise) ist malicious, suspicious oder unklar?
- Welche Informationen fehlen für eine Entscheidung?

## Schritt-für-Schritt-Anleitung

### 1. Incident Overview (Incidentübersicht) prüfen

Dokumentiere:

| Feld | Beobachtung |
|---|---|
| Incident Summary (Incidentzusammenfassung) |  |
| Severity (Schweregrad) |  |
| Status |  |
| Anzahl Alerts (Warnungen) |  |
| Betroffene Assets (Bestand) |  |
| Empfohlene Aktionen |  |
| Remediation Status (Behebungsstatus) |  |

### 2. Alert Story (Warnungsverlauf) öffnen

Öffne den wichtigsten Alert (Warnung) und prüfe:

- What happened (Was ist passiert),
- Actions taken (Durchgeführte Aktionen),
- Related events (Zugehörige Ereignisse),
- Detection Source (Erkennungsquelle),
- MITRE ATT&CK Technique (MITRE-ATT&CK-Technik),
- Prozess- oder E-Mail-Kontext.

| Alert (Warnung)-Feld | Beobachtung |
|---|---|
| Alert Title (Warnungstitel) |  |
| Detection Source (Erkennungsquelle) |  |
| Initiating Process (auslösender Prozess) |  |
| Target Process/File (Zielprozess/-datei) |  |
| Command Line (Befehlszeile) |  |
| Account (Konto) |  |
| Device (Gerät) |  |
| Zeitpunkt |  |

### 3. Evidence (Beweise) und Entities (Entitäten) auswerten

| Entity (Entität)/Evidence (Beweise) | Wert | Verdict (Bewertung) | Bewertung |
|---|---|---|---|
| Device (Gerät) |  |  |  |
| User |  |  |  |
| File/Hash |  |  |  |
| Process |  |  |  |
| IP/URL |  |  |  |

Prüfe bei Dateien:

- Pfad,
- SHA256,
- digitale Signatur,
- Verbreitung im Tenant,
- erstmaliges und letztes Auftreten,
- zugehörige Prozesse.

### 4. Device Page (Geräteseite) öffnen

Prüfe:

| Bereich | Leitfrage |
|---|---|
| Overview (Übersicht) | Ist das Gerät aktiv und onboarded? |
| Alerts (Warnungen) | Gibt es weitere Alerts (Warnungen)? |
| Logged-on users (angemeldete Benutzer) | Welcher Benutzer war aktiv? |
| Timeline (Zeitachse) | Welche Ereignisse liegen vor und nach dem Alert (Warnung)? |
| Software inventory (Softwarebestand) | Ist die Anwendung bekannt und installiert? |
| Response actions (Antwortaktionen) | Wurden bereits Aktionen ausgeführt? |

### 5. Timeline (Zeitachse) eingrenzen

Nutze einen engen Zeitraum, beispielsweise 15 Minuten vor bis 30 Minuten nach dem Alert (Warnung).

Suche nach:

- Process events (Prozessereignisse),
- File events (Dateiereignisse),
- Network events (Netzwerkereignisse),
- Registry events (Registrierungsereignisse),
- Security-control events (Sicherheitssteuerungsereignisse).

Dokumentiere die Prozesskette:

```text
<Parent Process (übergeordneter Prozess)>
-> <Child Process (untergeordneter Prozess)>
-> <Folgeprozess oder Datei>
-> <Netzwerkziel>
```

| Ebene | Prozess/Datei | Pfad oder Command Line (Befehlszeile) | Bewertung |
|---:|---|---|---|
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |
| 4 |  |  |  |

## KQL-Ergänzung

Alerts (Warnungen) und zugehörige Evidence (Beweise) verbinden:

```kql
let RecentAlerts =
    AlertInfo
    | where Timestamp > ago(7d)
    | project AlertId, AlertTitle=Title, AlertSeverity=Severity,
              ServiceSource, DetectionSource, AlertTime=Timestamp;
RecentAlerts
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(7d)
    | project AlertId, EntityType, EvidenceRole, EvidenceDirection,
              DeviceName, AccountName, AccountUpn, FileName, FolderPath,
              SHA256, RemoteIP, RemoteUrl, ProcessCommandLine
) on AlertId
| project AlertTime, AlertTitle, AlertSeverity, ServiceSource,
          EntityType, DeviceName, AccountUpn, FileName, FolderPath,
          SHA256, RemoteIP, RemoteUrl, ProcessCommandLine
| order by AlertTime desc
```

Prozessaktivitäten auf einem konkreten Gerät im Incident-Zeitraum:

```kql
let DeviceToCheck = "DEVICE-NAME-HERE";
let IncidentTime = datetime(2026-07-14 08:00:00);
DeviceProcessEvents
| where DeviceName =~ DeviceToCheck
| where Timestamp between (IncidentTime - 15m .. IncidentTime + 30m)
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp asc
```

Netzwerkverbindungen im selben Zeitraum:

```kql
let DeviceToCheck = "DEVICE-NAME-HERE";
let IncidentTime = datetime(2026-07-14 08:00:00);
DeviceNetworkEvents
| where DeviceName =~ DeviceToCheck
| where Timestamp between (IncidentTime - 15m .. IncidentTime + 30m)
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort,
          RemoteUrl, Protocol, ActionType
| order by Timestamp asc
```

## PowerShell-Ergänzung

Lokale Prozessinformationen, falls der Prozess noch läuft:

```powershell
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
    Sort-Object ParentProcessId, ProcessId
```

Datei prüfen:

```powershell
$FilePath = "C:\Path\To\File.exe"

Get-FileHash -Path $FilePath -Algorithm SHA256
Get-AuthenticodeSignature -FilePath $FilePath
Get-Item $FilePath | Select-Object FullName, Length, CreationTime, LastWriteTime,
    @{Name="CompanyName";Expression={$_.VersionInfo.CompanyName}},
    @{Name="FileVersion";Expression={$_.VersionInfo.FileVersion}}
```

> Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.

## Erwartetes Ergebnis

Erstelle eine kurze technische Bewertung:

```text
Der Incident begann mit <Prozess/Alert (Warnung)> auf <Gerät> unter <Benutzer>.
Die auffällige Aktivität bestand aus <Prozesskette>.
Weitere Datei-/Netzwerkaktivitäten: <Beschreibung>.
Tenantweite Verbreitung: <ein Gerät / mehrere Geräte>.
Vorläufige Bewertung: <legitim / verdächtig / wahrscheinlich bösartig>.
Empfohlener nächster Schritt: <Aktion>.
```

## Diskussionsfragen

- Welche Evidence (Beweise) ist entscheidend und welche nur Kontext?
- Warum reicht eine Microsoft-Signatur nicht als Freigabe?
- Welche Business-Informationen fehlen dem MSSP typischerweise?
- Wann sollte die Untersuchung auf weitere Geräte ausgeweitet werden?

## Merksatz

Eine belastbare Incident-Bewertung entsteht erst aus dem Zusammenhang von Alert (Warnung), Evidence (Beweise), Entity (Entität), Prozesskette, Benutzer, Zeitpunkt und Folgeaktivität.
