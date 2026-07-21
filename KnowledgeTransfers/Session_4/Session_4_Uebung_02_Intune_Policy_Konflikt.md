# Session 4 – Übung 2
## Intune Policy Error oder Conflict untersuchen

## Praxissituation

Nach einer Änderung an der Defender-AV-Policy zeigt ein Windows-11-Gerät im Intune Admin Center den Status `Conflict`. Auf dem Gerät ist außerdem ein anderer Wert wirksam als in der vorgesehenen Endpoint-Security-Policy.

Im Betrieb kann dies entstehen, wenn dieselbe Einstellung zusätzlich durch eine Security Baseline, ein Settings Catalog Profile oder eine bestehende Gruppenrichtlinie gesetzt wird. Ohne systematische Prüfung besteht die Gefahr, dass die falsche Policy geändert oder ein breiter Rollout unnötig zurückgenommen wird.

## Ziel

Die Teilnehmer identifizieren die relevanten Konfigurationsquellen, prüfen den Intune-Status und vergleichen den zentralen Zielwert mit dem lokalen Ist-Zustand.

## Voraussetzungen

- Leserechte im Intune Admin Center
- Zugriff auf Endpoint-Security-Policies und Konfigurationsprofile
- lokaler administrativer Zugriff auf ein freigegebenes Testgerät oder Remote-PowerShell
- keine produktive Policy-Änderung während der Übung

## Schritt-für-Schritt-Anleitung

### 1. Betroffene Policy öffnen

Navigiere in Intune zu dem relevanten Richtlinientyp, zum Beispiel:

```text
Endpoint security (Endpunktsicherheit)
-> Antivirus (Antivirus)
-> <betroffene Policy>
```

Prüfe:

- Settings (Einstellungen)
- Assignments (Zuweisungen)
- Device status (Gerätestatus)
- Per-setting status (Status pro Einstellung)

Öffne das betroffene Gerät und identifiziere die konkrete Einstellung mit Error (Fehler) oder Conflict (Konflikt).

### 2. Zielwert festhalten

Ermittle aus der Policy den vorgesehenen Wert, zum Beispiel:

```text
Allow real-time monitoring (Echtzeitüberwachung zulassen) = Enabled (Aktiviert)
```

Notiere gedanklich:

- Name der Einstellung,
- gewünschter Wert,
- Policy-Name,
- Assignment-Gruppe.

### 3. Weitere Intune-Quellen prüfen

Suche nach derselben oder semantisch vergleichbaren Einstellung in:

```text
Endpoint security (Endpunktsicherheit)
-> Security baselines (Sicherheitsbaselines)

Devices (Geräte)
-> Configuration (Konfiguration)
-> Policies (Richtlinien)
-> Settings catalog (Einstellungskatalog)
```

Prüfe insbesondere, ob das betroffene Gerät gleichzeitig mehreren Profilen zugewiesen ist.

### 4. Gruppenrichtlinieneinfluss berücksichtigen

Auf dem Testgerät:

```powershell
gpresult /h "$env:TEMP\gpresult.html"
Start-Process "$env:TEMP\gpresult.html"
```

Suche im Bericht nach:

- Microsoft Defender Antivirus,
- Windows Update,
- Windows Components,
- Security Settings,
- relevanten Registry-basierten Einstellungen.

In einer Hybrid-Umgebung kann eine alte GPO weiterhin wirksam sein, obwohl Intune die Zielplattform ist.

### 5. Lokalen Defender-Ist-Zustand prüfen

```powershell
Get-MpComputerStatus | Select-Object `
    AMRunningMode,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    AMServiceEnabled,
    IsTamperProtected,
    AntivirusSignatureLastUpdated

Get-MpPreference | Select-Object `
    DisableRealtimeMonitoring,
    DisableBehaviorMonitoring,
    DisableIOAVProtection,
    DisableScriptScanning,
    PUAProtection,
    SignatureFallbackOrder,
    SignatureUpdateInterval
```

Achte auf negative Einstellungsnamen:

```text
DisableRealtimeMonitoring = False
```

bedeutet, dass Echtzeitüberwachung nicht deaktiviert und damit grundsätzlich aktiviert ist.

### 6. Defender-Konfigurationsänderungen im Event Log prüfen

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Windows Defender/Operational'
    Id        = 5007
    StartTime = (Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Id, Message | Format-List
```

Event ID `5007` zeigt Änderungen an Defender-Konfigurationen. Prüfe Zeitstempel und geänderten Registry-/Preference-Wert.

### 7. MDM-Ereignisse prüfen

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' -MaxEvents 150 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List
```

Suche nach Fehlern im Zeitraum des letzten Intune-Syncs oder der Policy-Änderung.

### 8. Gerät synchronisieren und erneut prüfen

Im Intune Admin Center:

```text
Devices (Geräte)
-> Windows (Windows)
-> <Gerät>
-> Sync (Synchronisieren)
```

Alternativ lokal über:

```text
Settings (Einstellungen)
-> Accounts (Konten)
-> Access work or school (Auf Arbeits- oder Schulkonto zugreifen)
-> <Verbindung>
-> Info (Informationen)
-> Sync (Synchronisieren)
```

Warte auf die Verarbeitung und prüfe Portalstatus sowie lokalen Ist-Wert erneut.

### 9. Ursache korrekt behandeln

Nur die tatsächlich ursächliche Quelle sollte angepasst werden. Typische Ergebnisse:

- doppelte Intune-Konfiguration entfernen,
- alte GPO nach Change-Prozess bereinigen,
- falsches Assignment korrigieren,
- Gerät aus falscher Pilot-/Produktionsgruppe entfernen,
- Trellix-Restbestand beseitigen,
- bei veraltetem Reporting auf nächsten Check-in warten.

> Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.

## Kurze Zusammenfassung

Die Teilnehmer haben einen Intune-Konflikt systematisch untersucht. Sie haben Zielwert, mögliche Policy-Quellen, Gruppenrichtlinien, lokalen Defender-Zustand und relevante Event Logs miteinander verglichen und können die ursächliche Konfigurationsquelle statt nur das sichtbare Symptom korrigieren.
