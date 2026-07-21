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


### 1. Action Center (Aktionscenter) prüfen

Das Action Center findet sich unter https://security.microsoft.com/action-center/ oder im Portal unter 
**Investigation & Response (Untersuchung & Antwort) -> Actions & Submissions (Aktionen & Übermittlungen)**

Prüfe beide Bereiche:

- `Pending (Ausstehend)`
- `History (Verlauf)` beziehungsweise abgeschlossene Aktionen

Die AIR-Investigations finden sich auch unter https://security.microsoft.com/airinvestigation

### 2. Automation Level (Automatisierungsebene) diskutieren

Ermittle, ob die betroffenen Geräte einer Device Group (Gerätegruppe) mit Full-, Semi- oder No-Automation (Voll-, Teil- oder keine Automatisierung) zugeordnet sind. [hierzu hilft die Anelitung aus der Microsoft Dokumentation: https://learn.microsoft.com/en-us/defender-endpoint/configure-automated-investigations-remediation?view=o365-worldwide]

Beschreibung der Automations-Level-Stufen:

| Automation Level (Automatisierungsebene) | Betriebswirkung |
|---|---|
| Full (Vollautomatisch) | Geeignete Remediation (Behebung) wird automatisch ausgeführt |
| Semi (Teilautomatisch) | Bestimmte oder alle Maßnahmen benötigen Freigabe |
| No automated response (Keine automatisierte Reaktion) | Keine automatische Investigation (Untersuchung)/Remediation (Behebung); nicht als Zielzustand empfohlen |

**Achtung!!** Wie unter  https://learn.microsoft.com/en-us/defender-endpoint/automation-levels beschrieben, wird es bei AIR eine Änderung ab September geben und diese nicht mehr separat steuerbar sein. 

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



## Diskussionsfragen

- Wann ist Full Automation (Vollautomatisierung) sinnvoll?
- Welche Gerätetypen benötigen eventuell Semi Automation (Teilautomatisierung)?
- Wann darf eine Remediation (Behebung) rückgängig gemacht werden?
- Wie verhindert man, dass Pending Actions (ausstehende Aktionen) unbearbeitet bleiben?
- Welche Aufgaben übernimmt später das MSSP?

## Merksatz

AIR automatisiert Analyse und Remediation (Behebung). Das Action Center (Aktionscenter) macht sichtbar, was vorgeschlagen, ausgeführt oder rückgängig gemacht wurde.
