# Session 3 - Übung 4
## Automated Investigation & Response und Action Center auswerten

## Praxissituation

Ein Incident zeigt den Hinweis, dass Microsoft Defender eine automatisierte Untersuchung gestartet und eine Datei als `Malicious` bewertet hat. Im Action Center befindet sich außerdem eine Pending Action. Die interne IT muss prüfen, ob die Maßnahme genehmigt werden kann und was bereits automatisch passiert ist.

## Ziel der Übung

Die Teilnehmer sollen AIR-Ergebnisse, Evidence-Verdicts, Pending Actions und Completed Actions nachvollziehen und eine dokumentierte Freigabeentscheidung vorbereiten.

## Benötigte Berechtigungen

- Leserechte auf Investigations und Action Center
- Für Approve/Reject entsprechende Remediation-Rechte
- Schulungsfall, Testincident oder bereits abgeschlossene Investigation

## Wichtiger Sicherheitshinweis

In dieser Übung sollen keine produktiven Pending Actions ohne Freigabe genehmigt oder abgelehnt werden. Eine reale Aktion kann Dateien, Prozesse, Dienste, Registry Keys oder Scheduled Tasks verändern.

## Ausgangspunkt

Mögliche Einstiege:

```text
Incident -> Investigations
Device Page -> Action center
Defender Portal -> Action center
```

## Aufgabe

Wähle eine vorhandene Investigation oder Action und beantworte:

- Wie wurde die Investigation gestartet?
- Welche Evidence wurde untersucht?
- Welche Verdicts wurden vergeben?
- Welche Remediation wurde vorgeschlagen oder ausgeführt?
- Wartet eine Aktion auf Freigabe?
- Kann eine ausgeführte Aktion rückgängig gemacht werden?

## Schritt-für-Schritt-Anleitung

### 1. Investigation Details öffnen

Dokumentiere:

| Feld | Beobachtung |
|---|---|
| Investigation Name/ID |  |
| Startzeit |  |
| Auslöser | Alert / manuell |
| Status |  |
| Betroffene Geräte |  |
| Anzahl Evidence |  |
| Remediation Status |  |

### 2. Evidence-Verdicts prüfen

| Evidence | Typ | Verdict | Begründung/Details | Maßnahme |
|---|---|---|---|---|
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |

Mögliche Verdicts:

| Verdict | Bedeutung |
|---|---|
| Malicious | Als bösartig bewertet |
| Suspicious | Verdächtig, aber nicht eindeutig bestätigt |
| No threats found | Keine bestätigte Bedrohung gefunden |

### 3. Action Center prüfen

Prüfe beide Bereiche:

- `Pending`
- `History` beziehungsweise abgeschlossene Aktionen

| Feld | Beobachtung |
|---|---|
| Action Type |  |
| Action Source |  |
| Target |  |
| Submitted by |  |
| Submitted Time |  |
| Status |  |
| Related Incident |  |
| Undo verfügbar? |  |

### 4. Pending Action bewerten

Beantworte vor einer Freigabe:

| Prüffrage | Antwort |
|---|---|
| Ist die Evidence tatsächlich bösartig? |  |
| Ist der Pfad plausibel oder Teil einer Fachanwendung? |  |
| Welche Business-Auswirkung hätte die Aktion? |  |
| Gibt es ein Backup oder eine Wiederherstellungsmöglichkeit? |  |
| Wer muss zustimmen? |  |
| Ist eine schnellere Containment-Maßnahme erforderlich? |  |

### 5. Automation Level diskutieren

Ermittle, ob die betroffenen Geräte einer Device Group mit Full-, Semi- oder No-Automation zugeordnet sind.

| Automation Level | Betriebswirkung |
|---|---|
| Full | Geeignete Remediation wird automatisch ausgeführt |
| Semi | Bestimmte oder alle Maßnahmen benötigen Freigabe |
| No automated response | Keine automatische Investigation/Remediation; nicht als Zielzustand empfohlen |

## KQL-Ergänzung

Alerts eines Geräts vor und nach einer AIR-Untersuchung anzeigen:

```kql
let DeviceToCheck = "DEVICE-NAME-HERE";
AlertEvidence
| where Timestamp > ago(30d)
| where DeviceName =~ DeviceToCheck
| join kind=leftouter (
    AlertInfo
    | where Timestamp > ago(30d)
    | project AlertId, AlertTitle=Title, Severity, ServiceSource,
              DetectionSource, AlertTime=Timestamp
) on AlertId
| project AlertTime, AlertTitle, Severity, ServiceSource,
          EntityType, EvidenceRole, FileName, FolderPath, SHA256,
          ProcessCommandLine
| order by AlertTime desc
```

Defender-Antivirus-Aktionen im Endpoint-Datensatz suchen:

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("Antivirus", "Malware", "Quarantine")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

Hinweis: Verfügbare `ActionType`-Werte im eingebauten Schema des eigenen Tenants prüfen.

## PowerShell-Ergänzung

Lokale Bedrohungserkennungen prüfen:

```powershell
Get-MpThreatDetection |
    Select-Object InitialDetectionTime, LastThreatStatusChangeTime,
        ThreatID, ThreatStatusID, ActionSuccess, Resources |
    Format-List
```

Bekannte Threats anzeigen:

```powershell
Get-MpThreat |
    Select-Object ThreatID, ThreatName, SeverityID, CategoryID, DidThreatExecute |
    Format-Table -AutoSize
```

> Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.

## Erwartetes Ergebnis

Erstelle einen Freigabevermerk:

```text
AIR untersuchte <Evidence> auf <Gerät> und vergab das Verdict <Verdict>.
Vorgeschlagene/ausgeführte Maßnahme: <Action>.
Business-Auswirkung: <Bewertung>.
Entscheidung: <Approve / Reject / weitere Analyse>.
Begründung und Freigabe: <Text>.
```

## Diskussionsfragen

- Wann ist Full Automation sinnvoll?
- Welche Gerätetypen benötigen eventuell Semi Automation?
- Wann darf eine Remediation rückgängig gemacht werden?
- Wie verhindert man, dass Pending Actions unbearbeitet bleiben?
- Welche Aufgaben übernimmt später das MSSP?

## Merksatz

AIR automatisiert Analyse und Remediation. Das Action Center macht sichtbar, was vorgeschlagen, ausgeführt oder rückgängig gemacht wurde.
