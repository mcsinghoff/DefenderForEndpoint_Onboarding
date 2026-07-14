# Session 3 - Übung 3
## Advanced Hunting und KQL: ähnliche Aktivitäten tenantweit suchen

## Praxissituation

Auf einem Windows-11-Gerät wurde eine auffällige PowerShell-Command-Line erkannt. Das Gerät wurde noch nicht als kompromittiert bestätigt. Das Security-Team fragt:

```text
Ist diese Aktivität nur auf diesem Gerät aufgetreten oder auf weiteren Clients?
```

Eine einzelne Device Timeline beantwortet diese Frage nicht ausreichend.

## Ziel der Übung

Die Teilnehmer sollen eine KQL-Query schrittweise aufbauen, Ergebnisse gruppieren und den Scope einer möglichen Bedrohung tenantweit bewerten.

## Benötigte Berechtigungen

- Zugriff auf Advanced Hunting
- Leserechte auf Endpoint-Telemetrie
- Kenntnis eines Testprozesses, Hashes oder Geräts

## Ausgangspunkt

```text
https://security.microsoft.com
Hunting -> Advanced hunting
```

## Aufgabe

Suche nach PowerShell-Prozessen mit auffälligen Parametern und beantworte:

- Auf welchen Geräten trat das Muster auf?
- Welche Benutzer waren beteiligt?
- Wie häufig trat es auf?
- Welche Parent-Prozesse waren beteiligt?
- Handelt es sich um einen bekannten IT-Prozess oder eine mögliche Bedrohung?

## KQL-Grundlagen

### 1. Tabelle und Zeitraum

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
```

### 2. Prozess filtern

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
```

### 3. Auffällige Parameter filtern

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "FromBase64String",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX"
)
```

### 4. Benötigte Spalten auswählen

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "FromBase64String",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX"
)
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

## Schritt-für-Schritt-Auswertung

### 1. Einzelereignisse prüfen (optional)

Dokumentiere drei repräsentative Treffer:

| Zeitpunkt | Gerät | Benutzer | Parent | Command Line | Bewertung |
|---|---|---|---|---|---|
|  |  |  |  |  |  |
|  |  |  |  |  |  |
|  |  |  |  |  |  |

### 2. Nach Gerät gruppieren

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "FromBase64String",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX"
)
| summarize EventCount=count(),
            FirstSeen=min(Timestamp),
            LastSeen=max(Timestamp),
            Users=dcount(AccountName)
  by DeviceName
| order by EventCount desc
```

### 3. Nach Parent-Prozess gruppieren

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "FromBase64String",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX"
)
| summarize EventCount=count(), Devices=dcount(DeviceName)
  by InitiatingProcessFileName
| order by EventCount desc
```

### 4. Exakten Hash suchen

```kql
let TargetHash = "SHA256-HERE";
union DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 =~ TargetHash
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 5. Netzwerkaktivität des Prozesses prüfen

```kql
let DeviceToCheck = "DEVICE-NAME-HERE";
let StartTime = ago(7d);
DeviceNetworkEvents
| where Timestamp > StartTime
| where DeviceName =~ DeviceToCheck
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort,
          RemoteUrl, ActionType
| order by Timestamp desc
```

## Query-Optimierung

| Gute Praxis | Begründung |
|---|---|
| Zeitraum früh filtern | Reduziert Datenmenge |
| Präzise Prozessfilter | Verhindert unnötige Treffer |
| Nur benötigte Spalten projizieren | Verbessert Lesbarkeit und Performance |
| Erst testen, dann `join` verwenden | Komplexität schrittweise erhöhen |
| Ergebnisse nach Häufigkeit und Geräten gruppieren | Erleichtert Scope-Bewertung |
| Query kommentieren und speichern | Wiederverwendung und Übergabe |

## Diskussionsfragen

- Welche Teile der Query eignen sich für eine spätere Custom Detection?
- Welche legitimen IT-Tools können ähnliche Command Lines erzeugen?
- Wie verhindert man eine zu große False-Positive-Rate?

## Merksatz

Advanced Hunting erweitert die Sicht vom einzelnen Gerät auf den gesamten Tenant. Erst dadurch lässt sich der tatsächliche Scope einer Aktivität bewerten.
