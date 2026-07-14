# Session 3 - Übung 4
## Automated Investigation & Response (Automatisierte Untersuchung und Reaktion) und Action Center (Aktionscenter) auswerten

## Praxissituation

Ein Incident zeigt den Hinweis, dass Microsoft Defender eine automatisierte Untersuchung gestartet und eine Datei als `Malicious (Bösartig)` bewertet hat. Im Action Center (Aktionscenter) befindet sich außerdem eine Pending Action (ausstehende Aktion). Die interne IT muss prüfen, ob die Maßnahme genehmigt werden kann und was bereits automatisch passiert ist.

## Ziel der Übung

Die Teilnehmer sollen AIR-Ergebnisse, Evidence (Beweise)-Verdicts (Bewertungen), Pending Actions (ausstehende Aktionen) und Completed Actions (abgeschlossene Aktionen) nachvollziehen und eine dokumentierte Freigabeentscheidung vorbereiten.

## Benötigte Berechtigungen

- Leserechte auf Investigations (Untersuchungen) und Action Center (Aktionscenter)
- Für Approve (Genehmigen)/Reject (Ablehnen) entsprechende Remediation (Behebung)-Rechte
- Schulungsfall, Testincident oder bereits abgeschlossene Investigation (Untersuchung)

## Wichtiger Sicherheitshinweis

In dieser Übung sollen keine produktiven Pending Actions (ausstehende Aktionen) ohne Freigabe genehmigt oder abgelehnt werden. Eine reale Aktion kann Dateien, Prozesse, Dienste, Registry Keys oder Scheduled Tasks verändern.

## Ausgangspunkt

Mögliche Einstiege:

```text
Incident -> Investigations (Untersuchungen)
Device Page (Geräteseite) -> Action center (Aktionscenter)
Actions & submissions (Aktionen & Übermittlungen) -> Action center (Aktionscenter)
```

## Aufgabe

Wähle eine vorhandene Investigation (Untersuchung) oder Action und beantworte:

- Wie wurde die Investigation (Untersuchung) gestartet?
- Welche Evidence (Beweise) wurde untersucht?
- Welche Verdicts (Bewertungen) wurden vergeben?
- Welche Remediation (Behebung) wurde vorgeschlagen oder ausgeführt?
- Wartet eine Aktion auf Freigabe?
- Kann eine ausgeführte Aktion rückgängig gemacht werden?

## Schritt-für-Schritt-Anleitung

### 1. Investigation Details (Untersuchungsdetails) öffnen

Dokumentiere:

| Feld | Beobachtung |
|---|---|
| Investigation Name/ID (Untersuchungsname/-ID) |  |
| Startzeit |  |
| Auslöser | Alert (Warnung) / manuell |
| Status |  |
| Betroffene Geräte |  |
| Anzahl Evidence (Beweise) |  |
| Remediation Status (Behebungsstatus) |  |

### 2. Evidence (Beweise)-Verdicts (Bewertungen) prüfen

| Evidence (Beweise) | Typ | Verdict (Bewertung) | Begründung/Details | Maßnahme |
|---|---|---|---|---|
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |

Mögliche Verdicts (Bewertungen):

| Verdict (Bewertung) | Bedeutung |
|---|---|
| Malicious (Bösartig) | Als bösartig bewertet |
| Suspicious (Verdächtig) | Verdächtig, aber nicht eindeutig bestätigt |
| No threats found (Keine Bedrohungen gefunden) | Keine bestätigte Bedrohung gefunden |

### 3. Action Center (Aktionscenter) prüfen

Prüfe beide Bereiche:

- `Pending (Ausstehend)`
- `History (Verlauf)` beziehungsweise abgeschlossene Aktionen

| Feld | Beobachtung |
|---|---|
| Action Type (Aktionstyp) |  |
| Action Source (Aktionsquelle) |  |
| Target (Ziel) |  |
| Submitted by (Übermittelt von) |  |
| Submitted Time (Übermittlungszeit) |  |
| Status |  |
| Related Incident (Zugehöriger Incident) |  |
| Undo (Rückgängig machen) verfügbar? |  |

### 4. Pending Action (ausstehende Aktion) bewerten

Beantworte vor einer Freigabe:

| Prüffrage | Antwort |
|---|---|
| Ist die Evidence (Beweise) tatsächlich bösartig? |  |
| Ist der Pfad plausibel oder Teil einer Fachanwendung? |  |
| Welche Business-Auswirkung hätte die Aktion? |  |
| Gibt es ein Backup oder eine Wiederherstellungsmöglichkeit? |  |
| Wer muss zustimmen? |  |
| Ist eine schnellere Containment-Maßnahme erforderlich? |  |

### 5. Automation Level (Automatisierungsebene) diskutieren

Ermittle, ob die betroffenen Geräte einer Device Group (Gerätegruppe) mit Full-, Semi- oder No-Automation (Voll-, Teil- oder keine Automatisierung) zugeordnet sind.

| Automation Level (Automatisierungsebene) | Betriebswirkung |
|---|---|
| Full (Vollautomatisch) | Geeignete Remediation (Behebung) wird automatisch ausgeführt |
| Semi (Teilautomatisch) | Bestimmte oder alle Maßnahmen benötigen Freigabe |
| No automated response (Keine automatisierte Reaktion) | Keine automatische Investigation (Untersuchung)/Remediation (Behebung); nicht als Zielzustand empfohlen |

## KQL-Ergänzung

Alerts (Warnungen) eines Geräts vor und nach einer AIR-Untersuchung anzeigen:

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
AIR untersuchte <Evidence (Beweise)> auf <Gerät> und vergab das Verdict (Bewertung) <Verdict (Bewertung)>.
Vorgeschlagene/ausgeführte Maßnahme: <Action>.
Business-Auswirkung: <Bewertung>.
Entscheidung: <Approve (Genehmigen) / Reject (Ablehnen) / weitere Analyse>.
Begründung und Freigabe: <Text>.
```

## Diskussionsfragen

- Wann ist Full Automation (Vollautomatisierung) sinnvoll?
- Welche Gerätetypen benötigen eventuell Semi Automation (Teilautomatisierung)?
- Wann darf eine Remediation (Behebung) rückgängig gemacht werden?
- Wie verhindert man, dass Pending Actions (ausstehende Aktionen) unbearbeitet bleiben?
- Welche Aufgaben übernimmt später das MSSP?

## Merksatz

AIR automatisiert Analyse und Remediation (Behebung). Das Action Center (Aktionscenter) macht sichtbar, was vorgeschlagen, ausgeführt oder rückgängig gemacht wurde.
