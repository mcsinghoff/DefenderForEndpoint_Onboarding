# Session 5 – Übung 5
## ASR-Policy kontrolliert ändern, validieren und zurückrollen

## Praxissituation

Die ASR-Regel `Block Office applications from creating child processes` wurde mehrere Wochen im Audit Mode betrieben. Die Auswertung zeigt, dass die bekannten Treffer bewertet wurden und die Regel auf einem freigegebenen Testgerät in den Block Mode überführt werden soll.

Die Änderung darf nicht direkt auf die gesamte Windows-11-Flotte wirken. Die IT muss eine Pilotänderung durchführen, den lokalen Zustand validieren und den vorherigen Auditzustand anschließend kontrolliert wiederherstellen.

## Ziel

Die Teilnehmer durchlaufen einen vollständigen Security-Policy-Change:

```text
Ausgangszustand prüfen
-> Pilot-Scope validieren
-> Einstellung ändern
-> Testgerät synchronisieren
-> Intune- und lokalen Zustand kontrollieren
-> Rollback durchführen
-> ursprünglichen Zustand nachweisen
```

## Voraussetzungen

- vorbereitete Schulungs- oder Pilot-ASR-Policy
- freigegebene Pilotgruppe mit einem ungefährlichen Testgerät
- Rolle `Endpoint Security Manager` oder geeignete Custom Intune Role
- lokaler administrativer Lesezugriff auf das Testgerät
- keine Produktionsgruppe in der Assignment-Liste
- Change-/Übungsfreigabe

## Wichtiger Sicherheitshinweis

Diese Übung ausschließlich mit einer vorbereiteten Pilotpolicy und einem Testgerät durchführen. Keine bestehende Produktionspolicy verändern und keine Produktionsgruppe zuweisen.

## Schritt-für-Schritt-Anleitung

### 1. Ausgangszustand in Intune prüfen

Navigiere zu:

```text
Intune admin center
-> Endpoint security (Endpunktsicherheit)
-> Attack surface reduction (Verringerung der Angriffsfläche)
```

Öffne die vorbereitete Pilotpolicy.

Prüfe:

- Policy name (Policyname),
- Platform (Plattform),
- Profile (Profil),
- Assignments (Zuweisungen),
- Excluded groups (ausgeschlossene Gruppen),
- Device status (Gerätestatus),
- Per-setting status (Status pro Einstellung).

Bestätige, dass ausschließlich die freigegebene Pilotgruppe zugewiesen ist.

### 2. Lokalen Ausgangszustand des Testgeräts prüfen

Führe auf dem Testgerät aus:

```powershell
$RuleId = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
$Preference = Get-MpPreference

for ($i = 0; $i -lt $Preference.AttackSurfaceReductionRules_Ids.Count; $i++) {
    if ($Preference.AttackSurfaceReductionRules_Ids[$i].ToString() -eq $RuleId) {
        [PSCustomObject]@{
            RuleId      = $RuleId
            ActionValue = [int]$Preference.AttackSurfaceReductionRules_Actions[$i]
            Action      = switch ([int]$Preference.AttackSurfaceReductionRules_Actions[$i]) {
                0 { 'Disabled' }
                1 { 'Block' }
                2 { 'Audit' }
                6 { 'Warn' }
                default { 'Other' }
            }
        }
    }
}
```

Erwarteter Ausgangszustand für die Übung:

```text
Action = Audit
ActionValue = 2
```

### 3. ASR-Audit-Telemetrie kurz kontrollieren

Öffne im Defender Portal:

```text
Reports (Berichte)
-> Endpoints (Endpunkte)
-> Attack surface reduction rules (Regeln zur Verringerung der Angriffsfläche)
-> Detections (Erkennungen)
```

Prüfe, ob für die ausgewählte Regel bereits bekannte Audit Events vorhanden sind und ob keine ungeklärten Fachanwendungen betroffen sind.

Optional mit Advanced Hunting (Erweiterte Suche):

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType has 'Asr'
| where AdditionalFields has 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
   or ActionType has 'OfficeChildProcess'
| project Timestamp, DeviceName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, FolderPath, AccountName
| order by Timestamp desc
```

Die im Tenant tatsächlich verfügbaren `ActionType`-Werte über das Hunting-Schema prüfen.

### 4. Pilotpolicy bearbeiten

Im Intune-Profil:

```text
Properties (Eigenschaften)
-> Configuration settings (Konfigurationseinstellungen)
-> Edit (Bearbeiten)
```

Suche:

```text
Block Office applications from creating child processes
(Office-Anwendungen am Erstellen untergeordneter Prozesse hindern)
```

Ändere ausschließlich in der vorbereiteten Pilotpolicy:

```text
Audit -> Block
```

Prüfe vor dem Speichern erneut:

- nur eine Regel wurde geändert,
- keine Exclusions wurden ergänzt,
- Assignments bleiben unverändert,
- nur Pilotgruppe ist betroffen.

Wähle anschließend `Review + save (Überprüfen und speichern)`.

### 5. Intune-Synchronisierung auslösen

Im Intune Admin Center:

```text
Devices (Geräte)
-> Windows (Windows)
-> Windows devices (Windows-Geräte)
-> freigegebenes Testgerät
-> Sync (Synchronisieren)
```

Alternativ lokal:

```text
Settings (Einstellungen)
-> Accounts (Konten)
-> Access work or school (Auf Arbeits- oder Schulkonto zugreifen)
-> verwaltete Arbeits- oder Schulkontoverbindung
-> Info
-> Sync (Synchronisieren)
```

Warte auf die Policy-Verarbeitung. Intune-Reporting kann zeitverzögert sein.

### 6. Intune-Status validieren

Öffne die Pilotpolicy und kontrolliere:

```text
Device status (Gerätestatus)
Per-setting status (Status pro Einstellung)
```

Der Zielwert sollte für das Testgerät erfolgreich oder ohne Konflikt erscheinen.

Bei `Pending (Ausstehend)` nicht vorschnell erneut ändern. Zuerst Check-in und Verarbeitungszeit berücksichtigen.

### 7. Lokalen Blockzustand validieren

Führe den PowerShell-Check aus Schritt 2 erneut aus.

Erwarteter Zustand:

```text
Action = Block
ActionValue = 1
```

Prüfe zusätzlich:

```powershell
Get-MpComputerStatus | Select-Object `
    AMRunningMode,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    IsTamperProtected
```

### 8. Keine absichtliche bösartige Prozesskette erzeugen

Für diese Übung ist kein schädliches Office-Dokument und kein künstlicher Angriff notwendig. Der Nachweis erfolgt über:

- Intune Configuration Settings,
- Per-setting Status,
- lokale ASR-Action,
- Defender-Konfigurationsereignisse.

Optional Event ID 5007 prüfen:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Windows Defender/Operational'
    Id        = 5007
    StartTime = (Get-Date).AddHours(-2)
} | Select-Object TimeCreated,Message
```

### 9. Rollback durchführen

Öffne dieselbe Pilotpolicy:

```text
Properties (Eigenschaften)
-> Configuration settings (Konfigurationseinstellungen)
-> Edit (Bearbeiten)
```

Setze die Regel zurück:

```text
Block -> Audit
```

Wähle `Review + save (Überprüfen und speichern)`.

Löse erneut eine Intune-Synchronisierung des Testgeräts aus.

### 10. Rollback validieren

Prüfe erneut:

- Intune Device Status,
- Per-setting Status,
- lokalen PowerShell-Wert.

Erwarteter Endzustand:

```text
Action = Audit
ActionValue = 2
```

### 11. Change-Abschluss nachvollziehen

Der technische Nachweis besteht aus:

```text
- ursprünglicher Auditwert bestätigt
- Pilotassignment bestätigt
- Blockwert über Intune gesetzt
- Blockwert lokal validiert
- Rollback auf Audit durchgeführt
- Auditwert lokal erneut validiert
- keine Produktionsgruppe betroffen
```

## Hinweis

> Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.

## Kurze Zusammenfassung

Die Teilnehmer haben einen ASR-Policy-Change ausschließlich im Pilot-Scope durchgeführt, den wirksamen lokalen Wert mit PowerShell nachgewiesen und anschließend einen technisch validierten Rollback auf den ursprünglichen Audit Mode ausgeführt.
