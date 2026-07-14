# Session 3 - Übung 2
## Incident Investigation mit Evidence, Entities und Device Timeline

## Praxissituation

Das MSSP meldet einen Incident mit dem Hinweis: `Suspicious PowerShell activity on a Windows 11 device`. Das MSSP benötigt von der internen IT Informationen zum Benutzer, zur Gerätekritikalität und dazu, ob die Prozesskette zu einem legitimen Administrations- oder Softwareverteilungsprozess gehört.

## Ziel der Übung

Die Teilnehmer sollen einen Incident technisch und betrieblich untersuchen und aus Alerts, Evidence, Entities, Device Page und Timeline eine nachvollziehbare Angriffsgeschichte erstellen.

## Benötigte Berechtigungen

- Leserechte auf Incidents, Alerts, Evidence und Devices
- Leserechte auf Device Timeline
- Optional Advanced Hunting
- Kein Ausführen produktiver Response Actions

## Aufgabe

Untersuche einen geeigneten Beispiel-Incident und beantworte:

- Welcher Prozess war der Ursprung?
- Welche Datei oder Command Line ist relevant?
- Welcher Benutzer war beteiligt?
- Gibt es weitere Geräte oder Alerts?
- Welche Evidence ist malicious, suspicious oder unklar?
- Welche Informationen fehlen für eine Entscheidung?

## Schritt-für-Schritt-Anleitung

### 1. Incident Overview prüfen

Dokumentiere:

| Feld | Beobachtung |
|---|---|
| Incident Summary |  |
| Severity |  |
| Status |  |
| Anzahl Alerts |  |
| Betroffene Assets |  |
| Empfohlene Aktionen |  |
| Remediation Status |  |

### 2. Alert Story öffnen

Öffne den wichtigsten Alert und prüfe:

- What happened,
- Actions taken,
- Related events,
- Detection Source,
- MITRE ATT&CK Technique,
- Prozess- oder E-Mail-Kontext.

| Alert-Feld | Beobachtung |
|---|---|
| Alert Title |  |
| Detection Source |  |
| Initiating Process |  |
| Target Process/File |  |
| Command Line |  |
| Account |  |
| Device |  |
| Zeitpunkt |  |

### 3. Evidence und Entities auswerten

| Entity/Evidence | Wert | Verdict | Bewertung |
|---|---|---|---|
| Device |  |  |  |
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

### 4. Device Page öffnen

Prüfe:

| Bereich | Leitfrage |
|---|---|
| Overview | Ist das Gerät aktiv und onboarded? |
| Alerts | Gibt es weitere Alerts? |
| Logged-on users | Welcher Benutzer war aktiv? |
| Timeline | Welche Ereignisse liegen vor und nach dem Alert? |
| Software inventory | Ist die Anwendung bekannt und installiert? |
| Response actions | Wurden bereits Aktionen ausgeführt? |

### 5. Timeline eingrenzen

Nutze einen engen Zeitraum, beispielsweise 15 Minuten vor bis 30 Minuten nach dem Alert.

Suche nach:

- Process events,
- File events,
- Network events,
- Registry events,
- Security-control events.

Dokumentiere die Prozesskette:

```text
<Parent Process>
-> <Child Process>
-> <Folgeprozess oder Datei>
-> <Netzwerkziel>
```

| Ebene | Prozess/Datei | Pfad oder Command Line | Bewertung |
|---:|---|---|---|
| 1 |  |  |  |
| 2 |  |  |  |
| 3 |  |  |  |
| 4 |  |  |  |

## KQL-Ergänzung

Alerts und zugehörige Evidence verbinden:

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
Der Incident begann mit <Prozess/Alert> auf <Gerät> unter <Benutzer>.
Die auffällige Aktivität bestand aus <Prozesskette>.
Weitere Datei-/Netzwerkaktivitäten: <Beschreibung>.
Tenantweite Verbreitung: <ein Gerät / mehrere Geräte>.
Vorläufige Bewertung: <legitim / verdächtig / wahrscheinlich bösartig>.
Empfohlener nächster Schritt: <Aktion>.
```

## Diskussionsfragen

- Welche Evidence ist entscheidend und welche nur Kontext?
- Warum reicht eine Microsoft-Signatur nicht als Freigabe?
- Welche Business-Informationen fehlen dem MSSP typischerweise?
- Wann sollte die Untersuchung auf weitere Geräte ausgeweitet werden?

## Merksatz

Eine belastbare Incident-Bewertung entsteht erst aus dem Zusammenhang von Alert, Evidence, Entity, Prozesskette, Benutzer, Zeitpunkt und Folgeaktivität.
