# Session 3 - Übung 7
## Custom Detection Rule aus einer Hunting Query entwerfen

## Praxissituation

Das Security-Team stellt fest, dass ein internes Administrationswerkzeug nur auf wenigen freigegebenen Admin-Geräten verwendet werden darf. In Advanced Hunting wurde das Tool jedoch wiederholt auf normalen Benutzergeräten gefunden.

Da dieses kundenspezifische Nutzungsmuster nicht zuverlässig durch eine vorhandene Microsoft-Detection abgedeckt wird, soll eine Custom Detection Rule entworfen werden.

## Ziel der Übung

Die Teilnehmer sollen aus einem klaren Use Case eine stabile Hunting Query, einen Alerttitel, Severity, Entitäten, Frequenz und ein Runbook ableiten.

## Benötigte Berechtigungen

- Advanced-Hunting-Leserechte
- Für das tatsächliche Erstellen einer Regel: Berechtigung zum Verwalten von Custom Detections
- Kenntnis der erlaubten Admin-Geräte oder Device Tags
- In der Übung keine produktive Aktivierung ohne Change-Freigabe

## Use Case

Beispielwerkzeug:

```text
PsExec.exe
```

Erlaubt ist die Verwendung nur auf Geräten mit definiertem Admin-Kontext. Auf normalen Windows-11-Clients soll die Ausführung einen Alert erzeugen.

## Schritt-für-Schritt-Anleitung

### 1. Use Case beschreiben

| Feld | Inhalt |
|---|---|
| Risiko | Unautorisierte Remote-Ausführung oder laterale Bewegung |
| Datenquelle | DeviceProcessEvents |
| Zielobjekt | Windows-11-Client |
| Erlaubte Nutzung | Nur freigegebene Admin-Geräte |
| Erwartete Reaktion | Triage, Benutzer-/Admin-Kontext prüfen, ggf. Isolation |

### 2. Basisquery erstellen

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "PsExec.exe"
| project Timestamp, DeviceId, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          SHA256, ReportId
```

### 3. Erlaubte Geräte ausschließen

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

In Produktion sollte eine wartbare Quelle wie Device Tags, eine Funktion oder eine kontrollierte Referenzliste bevorzugt werden.

### 4. False Positives prüfen

Führe die Query über 30 Tage aus:

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

### 5. Detection-Design festlegen

| Feld | Beispiel |
|---|---|
| Rule Name | Unauthorized PsExec execution on standard client |
| Alert Title | PsExec executed on non-approved Windows client |
| Description | PsExec wurde außerhalb der freigegebenen Admin-Geräte ausgeführt |
| Severity | Medium oder High je nach Umfeld |
| Category | Lateral movement / Execution |
| MITRE Technique | Pass the Hash / Remote Services je nach Use Case prüfen |
| Frequency | Beispielsweise stündlich |
| Impacted Entity | DeviceId/DeviceName |
| Recommended Action | Benutzer-/Admin-Kontext prüfen, Timeline untersuchen, Scope erweitern |

### 6. Query-Anforderungen prüfen

Die aktuelle Portaloberfläche zeigt bei der Erstellung, welche Spalten für Zeitstempel, Geräte- oder Account-Entities erforderlich sind. Die Query muss die vom Assistenten verlangten Felder enthalten.

Mindestens sinnvoll:

- `Timestamp`,
- `DeviceId`,
- `DeviceName`,
- `ReportId`,
- aussagekräftige Kontextspalten.

### 7. Response Actions bewusst wählen

Automatische Response Actions sollten erst nach ausreichender Pilotierung aktiviert werden.

| Option | Empfehlung |
|---|---|
| Nur Alert erzeugen | Für erste Pilotphase |
| Automated Investigation starten | Nach Validierung möglich |
| Gerät automatisch isolieren | Nur für sehr eindeutige und hochriskante Use Cases |
| Datei blockieren/quarantänisieren | Nur bei stabiler Hash-/Dateibewertung |

### 8. Runbook erstellen

```text
1. Alert übernehmen und Status auf In progress setzen.
2. Device Timeline um den Trefferzeitpunkt prüfen.
3. Benutzer und Change-/Support-Ticket validieren.
4. Weitere Geräte mit identischer Datei oder Command Line suchen.
5. Bei legitimer Nutzung Approved-Liste korrigieren.
6. Bei unautorisierter Nutzung MSSP/Security eskalieren.
7. Response Action abhängig von aktiver Gefahr auswählen.
8. Classification, Determination und Ergebnis dokumentieren.
```

## PowerShell-Ergänzung

PsExec oder andere Remote-Tools lokal suchen:

```powershell
Get-CimInstance Win32_Process |
    Where-Object { $_.Name -match 'PsExec|PAExec' } |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
```

Datei-Hash und Signatur prüfen:

```powershell
$FilePath = 'C:\Path\To\PsExec.exe'
Get-FileHash -Path $FilePath -Algorithm SHA256
Get-AuthenticodeSignature -FilePath $FilePath
```

> Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.

## Erwartetes Ergebnis

Die Teilnehmer liefern einen Detection-Steckbrief:

| Feld | Ergebnis |
|---|---|
| Use Case |  |
| Query |  |
| Zulässige Ausnahmen |  |
| False-Positive-Analyse |  |
| Severity |  |
| Frequency |  |
| Entity Mapping |  |
| Response Action |  |
| Owner |  |
| Review-Datum |  |

## Diskussionsfragen

- Wann ist eine Custom Detection besser als eine Intune-Policy?
- Welche Risiken entstehen bei automatischer Isolation?
- Wie wird die Approved-Liste gepflegt?
- Wer reagiert auf den Alert: MSSP oder interne IT?
- Wie wird verhindert, dass eine Detection nach Monaten unbrauchbar wird?

## Merksatz

Eine gute Custom Detection besteht nicht nur aus KQL. Sie benötigt einen klaren Use Case, niedrige False-Positive-Rate, korrektes Entity Mapping, einen Owner und ein getestetes Runbook.
