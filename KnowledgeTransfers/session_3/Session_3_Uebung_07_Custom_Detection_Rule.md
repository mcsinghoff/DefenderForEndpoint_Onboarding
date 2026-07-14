# Session 3 - Übung 7
## Custom Detection Rule (benutzerdefinierte Erkennungsregel) aus einer Hunting Query (Suchabfrage) entwerfen

## Praxissituation

Das Security-Team stellt fest, dass ein internes Administrationswerkzeug nur auf wenigen freigegebenen Admin-Geräten verwendet werden darf. In Advanced Hunting (Erweiterte Suche) wurde das Tool jedoch wiederholt auf normalen Benutzergeräten gefunden.

Da dieses kundenspezifische Nutzungsmuster nicht zuverlässig durch eine vorhandene Microsoft-Detection abgedeckt wird, soll eine Custom Detection Rule (benutzerdefinierte Erkennungsregel) entworfen werden.

## Ziel der Übung

Die Teilnehmer sollen aus einem klaren Use Case eine stabile Hunting Query (Suchabfrage), einen Alerttitel, Severity (Schweregrad), Entitäten, Frequenz und ein Runbook ableiten.

## Benötigte Berechtigungen

- Advanced-Hunting (Bedrohungssuche)-Leserechte
- Für das tatsächliche Erstellen einer Regel: Berechtigung zum Verwalten von Custom Detections (benutzerdefinierte Erkennungen)
- Kenntnis der erlaubten Admin-Geräte oder Device (Gerät) Tags (Incidenttags)
- In der Übung keine produktive Aktivierung ohne Change-Freigabe

## Use Case

Beispielwerkzeug:

```text
PsExec.exe
```

Erlaubt ist die Verwendung nur auf Geräten mit definiertem Admin-Kontext. Auf normalen Windows-11-Clients soll die Ausführung einen Alert (Warnung) erzeugen.

## Schritt-für-Schritt-Anleitung

### 1.Basisquery erstellen

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "PsExec.exe"
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          SHA256, ReportId
```

### 2. Erlaubte Geräte ausschließen

Für eine Schulungsquery kann eine statische Liste verwendet werden:

```kql
let ApprovedAdminDevices = dynamic([
    "ADMIN-DEVICE-01",
    "ADMIN-DEVICE-02"
]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "PsExec.exe"
| where DeviceName !in~ (ApprovedAdminDevices)
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          SHA256, ReportId
```

In Produktion sollte eine wartbare Quelle wie Device (Gerät) Tags (Incidenttags), eine Funktion oder eine kontrollierte Referenzliste bevorzugt werden.

### 3. False Positives (Falsch-positive Ergebnisse) prüfen

Führe die Query (Abfrage) über 30 Tage aus:

```kql
let ApprovedAdminDevices = dynamic([
    "ADMIN-DEVICE-01",
    "ADMIN-DEVICE-02"
]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "PsExec.exe"
| where DeviceName !in~ (ApprovedAdminDevices)
| summarize Events=count(),
            FirstSeen=min(Timestamp),
            LastSeen=max(Timestamp),
            Users=make_set(AccountName, 20),
            Commands=make_set(ProcessCommandLine, 20)
  by DeviceId, DeviceName, SHA256
| order by Events desc
```

Prüfe:

- legitime Softwareverteilung,
- Support- oder Herstellerprozesse,
- Testgeräte,
- bekannte Admin-Nutzung,
- alternative Dateinamen oder Pfade.

### 4. Detection-Design festlegen

| Feld | Beispiel |
|---|---|
| Rule Name (Regelname) | Unauthorized PsExec execution on standard client |
| Alert Title (Warnungstitel) | PsExec executed on non-approved Windows client |
| Description (Beschreibung) | PsExec wurde außerhalb der freigegebenen Admin-Geräte ausgeführt |
| Severity (Schweregrad) | Medium (Mittel) oder High (Hoch) je nach Umfeld |
| Category (Kategorie) | Lateral movement / Execution |
| MITRE Technique | Pass the Hash / Remote Services je nach Use Case prüfen |
| Frequency (Häufigkeit) | Beispielsweise stündlich |
| Impacted Entity (betroffene Entität) | DeviceId/DeviceName |
| Recommended Action (empfohlene Aktion) | Benutzer-/Admin-Kontext prüfen, Timeline (Zeitachse) untersuchen, Scope erweitern |

### 5. Query (Abfrage)-Anforderungen prüfen

Die aktuelle Portaloberfläche zeigt bei der Erstellung, welche Spalten für Zeitstempel, Geräte- oder Account (Konto)-Entities (Entitäten) erforderlich sind. Die Query (Abfrage) muss die vom Assistenten verlangten Felder enthalten.

Mindestens sinnvoll:

- `Timestamp`,
- `DeviceId`,
- `DeviceName`,
- `ReportId`,
- aussagekräftige Kontextspalten.

### 6. Response Actions (Antwortaktionen) bewusst wählen

Automatische Response Actions (Antwortaktionen) sollten erst nach ausreichender Pilotierung aktiviert werden.

| Option | Empfehlung |
|---|---|
| Nur Alert (Warnung) erzeugen | Für erste Pilotphase |
| Automated Investigation (Automatisierte Untersuchung) starten | Nach Validierung möglich |
| Gerät automatisch isolieren | Nur für sehr eindeutige und hochriskante Use Cases |
| Datei blockieren/quarantänisieren | Nur bei stabiler Hash-/Dateibewertung |

### 7. Wenn vom organisatorischen prozess vorgegeben: Bearbeitungsablauf für den Alert definieren

```text
1. Alert (Warnung) übernehmen und Status auf In progress (In Bearbeitung) setzen.
2. Device Timeline (Gerätezeitachse) um den Trefferzeitpunkt prüfen.
3. Benutzer und Change-/Support-Ticket validieren.
4. Weitere Geräte mit identischer Datei oder Command Line (Befehlszeile) suchen.
5. Bei legitimer Nutzung Approved-Liste korrigieren.
6. Bei unautorisierter Nutzung MSSP/Security eskalieren.
7. Response Action (Antwortaktion) abhängig von aktiver Gefahr auswählen.
8. Classification (Klassifizierung), Determination (Bestimmung) und Ergebnis dokumentieren.
```

## PowerShell-Ergänzung

< leer, keine pwsh Ergänzung >

## Diskussionsfragen

- Wer reagiert auf welchen Alert (Warnung) der neu erstellt wird: MSSP oder interne IT?
- Wie wird verhindert, dass eine Detection nach Monaten unbrauchbar wird?

## Merksatz

Eine gute Custom Detection (benutzerdefinierte Erkennung) besteht nicht nur aus KQL. Sie benötigt einen klaren Use Case, niedrige False-Positive-Rate, korrektes Entity Mapping (Entitätszuordnung), einen Owner und ein getestetes Runbook.
