# Session 3 - Übung 6
## Live Response (Liveantwort) auf einem freigegebenen Testgerät

## Praxissituation

Das MSSP benötigt Echtzeitinformationen von einem verdächtigen Gerät. Ein Investigation Package (Untersuchungspaket) reicht nicht aus, weil geprüft werden soll, welche Prozesse und Netzwerkverbindungen aktuell bestehen. Für die Schulung steht ein ungefährliches, ausdrücklich freigegebenes Testgerät bereit.

## Ziel der Übung

Die Teilnehmer sollen eine Live-Response (Liveantwort)-Session sicher starten, ausschließlich lesende Untersuchungsbefehle verwenden, das Command Log (Befehlsprotokoll) prüfen und die Session kontrolliert beenden.

## Benötigte Berechtigungen

- Microsoft Defender for Endpoint Plan 2
- Live-Response (Liveantwort)-Berechtigung für die betreffende Device Group (Gerätegruppe)
- Aktivierte Live-Response (Liveantwort)-Funktion im Defender Portal
- Onboarded und erreichbares Windows-11-Testgerät
- Ausdrückliche Freigabe für die Übung

## Wichtige Sicherheitsregeln

- Nur auf dem benannten Testgerät arbeiten.
- Keine Dateien löschen, Prozesse stoppen oder Remediation (Behebung) ausführen.
- Keine unbekannten Skripte oder Binaries hochladen.
- Keine sensitiven Dateien herunterladen.
- Jede Session mit Ticket- oder Übungsreferenz dokumentieren.
- Command Log (Befehlsprotokoll) nach der Übung sichern oder dokumentieren.

## Ausgangspunkt

```text
Assets (Bestand) -> Devices (Geräte) -> <freigegebenes Testgerät>
-> Initiate live response session (Liveantwortsitzung initiieren)
```

## Aufgabe

Starte eine Live-Response (Liveantwort)-Session und erfasse:

- System- und Sitzungsinformationen,
- laufende Prozesse,
- aktive Netzwerkverbindungen,
- ausgewählte Dienste,
- Informationen zu einer bekannten ungefährlichen Datei.

## Schritt-für-Schritt-Anleitung

### 1. Testgerät validieren

| Prüffeld | Wert |
|---|---|
| Gerätename |  |
| Freigabe/Ticket |  |
| Device Group (Gerätegruppe) |  |
| Gerätestatus |  |
| Onboarding Status (Onboardingstatus) |  |
| Aktiver Benutzer |  |

### 2. Session starten

1. Öffne die Device Page (Geräteseite).
2. Wähle `Initiate live response session (Liveantwortsitzung initiieren)`.
3. Warte, bis die Verbindung hergestellt ist.
4. Prüfe Session Owner (Sitzungsverantwortlicher), Startzeit und Zielgerät.

### 3. Hilfe und verfügbare Befehle anzeigen

```text
help
```

Dokumentiere, welche Befehle für Basic und Advanced Live Response (Erweiterte Liveantwort) sichtbar sind.

### 4. Prozesse anzeigen

```text
processes
```

Suche ausschließlich beobachtend nach bekannten Prozessen wie:

- `explorer.exe`,
- `msedge.exe`,
- `SenseIR.exe` beziehungsweise Defender-Komponenten,
- `powershell.exe`, falls vorhanden.

| Prozess | PID | Erste Bewertung |
|---|---:|---|
|  |  |  |
|  |  |  |

### 5. Netzwerkverbindungen anzeigen

```text
connections
```

Optional im JSON-Format, sofern im Tenant unterstützt:

```text
connections -output json
```

| Prozess/PID | Remote-Ziel | Port | Bewertung |
|---|---|---:|---|
|  |  |  |  |
|  |  |  |  |

### 6. Dienste anzeigen

```text
services
```

Prüfe exemplarisch, ob sicherheitsrelevante Dienste sichtbar und gestartet sind. Keine Dienste stoppen.

### 7. Datei untersuchen

Nutze nur eine bekannte, ungefährliche Systemdatei, beispielsweise:

```text
fileinfo C:\Windows\System32\notepad.exe
```

Falls der Befehl im aktuellen Live-Response (Liveantwort)-Client anders benannt oder nicht verfügbar ist, zuerst `help` verwenden und die Portalhilfe beachten.

Optional kann eine Datei zur Defender-Analyse eingereicht werden, aber nur nach Freigabe. In der Übung erfolgt keine Einreichung unbekannter Dateien.

### 8. Command Log (Befehlsprotokoll) prüfen

Dokumentiere:

- ausgeführte Befehle,
- Zeitpunkte,
- Ergebnisse,
- aufgetretene Fehler.

### 9. Session beenden

1. Wähle `Disconnect session (Sitzung trennen)`.
2. Bestätige die Trennung.
3. Prüfe, dass die Session beendet ist.
4. Ergänze Ticket oder Übungsdokumentation.

## Optionale PowerShell-Vergleichsbefehle auf dem Testgerät

Prozesse:

```powershell
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

Netzwerkverbindungen:

```powershell
Get-NetTCPConnection |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
        State, OwningProcess
```

Dienste:

```powershell
Get-Service |
    Where-Object Status -eq 'Running' |
    Sort-Object Name |
    Select-Object Name, DisplayName, Status
```

Dateiinformationen:

```powershell
$FilePath = 'C:\Windows\System32\notepad.exe'
Get-FileHash -Path $FilePath -Algorithm SHA256
Get-AuthenticodeSignature -FilePath $FilePath
```

> Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.

## KQL-Ergänzung

Die in Live Response (Liveantwort) beobachteten Prozesse mit der historischen Telemetrie vergleichen:

```kql
let DeviceToCheck = "DEVICE-NAME-HERE";
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName =~ DeviceToCheck
| project Timestamp, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          AccountName, SHA256
| order by Timestamp desc
```

Netzwerkverbindungen vergleichen:

```kql
let DeviceToCheck = "DEVICE-NAME-HERE";
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName =~ DeviceToCheck
| project Timestamp, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort,
          RemoteUrl, Protocol, ActionType
| order by Timestamp desc
```


## Diskussionsfragen

- Wann reicht ein Investigation Package (Untersuchungspaket) und wann ist Live Response (Liveantwort) erforderlich?
- Wie wird verhindert, dass Live Response (Liveantwort) forensische Spuren unnötig verändert?
- Darf ein MSSP Dateien vom Gerät herunterladen?
- Sollen Incidents Response Prozesse dokumentiert werden in der Zukunft? Welche Freigaben und Aufbewahrungsregeln werden benötigt?

## Merksatz

Live Response (Liveantwort) ist keine normale Administrationskonsole. Es ist ein leistungsfähiges Incident-Response-Werkzeug und benötigt enge Rollen, Freigaben, Protokollierung und einen klaren Untersuchungszweck.
