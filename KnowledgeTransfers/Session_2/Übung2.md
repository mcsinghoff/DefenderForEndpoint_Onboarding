# Session 2 - Übung 2
## ASR-Audit-Ereignisse im Defender Portal auswerten

## Praxissituation

Nach zwei Wochen Pilotbetrieb fragt die IT-Leitung: "Welche ASR-Regeln hätten produktiv etwas blockiert, wenn wir schon im Block Mode wären?" Gleichzeitig möchten Fachbereiche wissen, ob ihre Anwendungen betroffen wären.

Diese Auswertung ist ein typischer Betriebsfall nach der MDE-Migration, weil ASR-Regeln vor einer produktiven Blockierung zunächst beobachtet und bewertet werden sollten.

## Ziel der Übung

Wir möchten ASR-Audit-Ereignisse im Microsoft Defender Portal finden, betroffene Geräte und Prozesse erkennen und eine erste Bewertung für den späteren Wechsel von Audit auf Block vorbereiten.

## Benötigte Berechtigungen

- Zugriff auf Microsoft Defender Portal
- Leserechte auf Endpoints, Reports und Geräteinformationen
- Optional Zugriff auf Advanced Hunting

## Ausgangspunkt

Portal:

```text
https://security.microsoft.com
```

Typischer Pfad:

```text
Reports -> Endpoints -> Attack surface reduction rules
```

Direkter Einstieg ist häufig auch möglich über:

```text
https://security.microsoft.com/asr
```

## Aufgabe

Prüfe die ASR-Audit-Ereignisse der letzten 7 bis 30 Tage und beantworte:

- Welche ASR-Regeln haben Ereignisse erzeugt?
- Welche Geräte sind betroffen?
- Welche Anwendungen oder Prozesse sind beteiligt?
- Welche Ereignisse wirken legitim?
- Welche Ereignisse wirken sicherheitsrelevant?
- Welche Regel könnte später auf Block oder Warn gestellt werden?

## Schritt-für-Schritt-Anleitung

### 1. ASR-Report öffnen

1. Öffne das Microsoft Defender Portal.
2. Navigiere zu:

   ```text
   Reports -> Endpoints -> Attack surface reduction rules
   ```

3. Öffne den Bereich `Detections`.
4. Setze den Zeitraum auf 7 oder 30 Tage.

### 2. Detections sichten

Prüfe die wichtigsten Spalten und Filter:

| Feld | Bedeutung |
|---|---|
| Rule | Welche ASR-Regel hat ausgelöst? |
| Device | Welches Gerät war betroffen? |
| User | Welcher Benutzer war beteiligt? |
| Application / Process | Welche Anwendung oder welcher Prozess war beteiligt? |
| Action | Audit, Warn oder Block |
| Time | Zeitpunkt des Ereignisses |

### 3. Top-Regeln identifizieren

Dokumentiere die häufigsten ASR-Regeln:

| ASR-Regel | Anzahl Ereignisse | Betroffene Geräte | Erste Bewertung |
|---|---:|---:|---|
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

### 4. Betroffene Geräte prüfen

Wähle ein Gerät mit ASR-Ereignissen aus und prüfe:

| Prüffeld | Beobachtung |
|---|---|
| Gerätename |  |
| Benutzer |  |
| ASR-Regel |  |
| Prozess / Anwendung |  |
| Pfad |  |
| Zeitpunkt |  |
| Audit oder Block |  |

### 5. Erste Bewertung vornehmen

Ordne das Ereignis ein:

| Kategorie | Wann zutreffend? | Bewertung |
|---|---|---|
| Wahrscheinlich legitim | Bekannte Fachanwendung, bekannter Admin-Prozess, erwartetes Verhalten | App-Owner prüfen, ggf. Ausnahme bewerten |
| Verdächtig | Ungewöhnlicher Prozess, Office startet Script/PowerShell, unbekannter Pfad | Security/MSSP prüfen lassen |
| Eindeutig unerwünscht | Malware-ähnliche Kette, unbekanntes Script, temporärer Downloadpfad | Regel für Block-Kandidat markieren |
| Unklar | Kontext fehlt | Weitere Investigation nötig |

## Optionale Advanced-Hunting-Abfrage

Falls Advanced Hunting verfügbar ist, kann eine einfache Abfrage verwendet werden:

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Asr"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ReportId
| order by Timestamp desc
```

Zusammenfassung nach Gerät und Aktion:

```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType startswith "Asr"
| summarize EventCount=count() by DeviceName, ActionType
| order by EventCount desc
```

Wenn die Abfrage keine Ergebnisse zeigt:

- Zeitraum erweitern
- prüfen, ob ASR-Policy wirklich zugewiesen ist
- prüfen, ob im Pilot überhaupt auslösende Ereignisse vorhanden sind

## Bewertung im Betriebsalltag

| Beobachtung | Nächste Aktion |
|---|---|
| Keine Events | Regel kann ggf. weiter im Audit bleiben oder kontrolliert auf Block getestet werden |
| Wenige legitime Events | App-Owner kontaktieren, mögliche Ausnahme prüfen |
| Viele Events auf vielen Geräten | Regel noch nicht blockieren, Ursachen analysieren |
| Events mit Office -> PowerShell | Security-relevant, genauer untersuchen |
| Events mit Admin-Skripten | IT-Betriebsprozess prüfen und dokumentieren |

## Diskussionsfragen

- Welche Regel hat die meisten Audit-Events erzeugt?
- Welche Anwendungen wären bei Block Mode betroffen?
- Welche Events sehen nach echtem Angriffsmuster aus?
- Welche Events benötigen App-Owner-Review?
- Welche Regel kann als nächstes in Warn oder Block pilotiert werden?

---
---

# POWERSHELL

---

### 1. Defender Operational Log prüfen

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 20 |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Format-List
```

---

### 2. ASR-Audit-Events suchen

ASR Audit Events erscheinen häufig mit Event ID `1122`.

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
    Where-Object { $_.Id -eq 1122 } |
    Select-Object TimeCreated, Id, Message |
    Format-List
```

---

### 3. ASR-Block-Events suchen

ASR Block Events erscheinen häufig mit Event ID `1121`.

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
    Where-Object { $_.Id -eq 1121 } |
    Select-Object TimeCreated, Id, Message |
    Format-List
```

---

### 4. ASR-Events der letzten 7 Tage ausgeben

```powershell
$StartTime = (Get-Date).AddDays(-7)

Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    Id = 1121,1122
    StartTime = $StartTime
} |
Select-Object TimeCreated, Id, Message |
Format-List
```

---

### 5. ASR-Events zählen

```powershell
$StartTime = (Get-Date).AddDays(-30)

Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    Id = 1121,1122
    StartTime = $StartTime
} |
Group-Object Id |
Select-Object Name, Count
```

---

### 6. Defender-Konfigurationsänderungen prüfen

Event ID `5007` zeigt Änderungen an Defender-Einstellungen.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    Id = 5007
    StartTime = (Get-Date).AddDays(-14)
} |
Select-Object TimeCreated, Id, Message |
Format-List
```
