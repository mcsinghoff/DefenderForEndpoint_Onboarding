# Session 2 - Übung 3
## Incident vs. Alert im Defender Portal unterscheiden

## Praxissituation

Ein möglicher MSSP meldet der internen IT: "Auf einem Client wurde ein Incident mit mehreren Alerts erzeugt." Die interne IT öffnet das Defender Portal und sieht mehrere Einträge. Es ist aber unklar, ob jeder Alert einzeln bearbeitet werden muss oder ob der Incident als gesamter Fall zu betrachten ist.


## Ziel der Übung

Wir sollen verstehen, wie Incidents und Alerts zusammenhängen, welche Informationen auf Incident-Ebene wichtig sind und wie man eine erste Orientierung im Defender Portal bekommt.

## Benötigte Berechtigungen

- Zugriff auf Microsoft Defender Portal
- Leserechte auf Incidents und Alerts
- Optional Zugriff auf betroffene Geräte und Evidence

## Ausgangspunkt

Portal:

```text
https://security.microsoft.com
```

Typische Pfade:

```text
Incidents & alerts -> Incidents
Incidents & alerts -> Alerts
```

## Aufgabe

Öffne einen Beispiel-Incident oder einen vorhandenen ungefährlichen Incident aus dem Tenant und beantworte:

- Wie viele Alerts gehören zum Incident?
- Welche Geräte oder Benutzer sind betroffen?
- Welche Severity hat der Incident?
- Welchen Status hat der Incident?
- Welche Evidence ist vorhanden?

## Schritt-für-Schritt-Anleitung

### 1. Incident Queue öffnen

1. Öffne das Microsoft Defender Portal.
2. Navigiere zu:

   ```text
   Incidents & alerts -> Incidents
   ```

3. Wähle einen geeigneten Incident aus.

> Hinweis: Für die Übung sollte kein aktiver kritischer Produktionsincident ohne Freigabe verwendet werden. Geeignet sind Demo-, Test- oder bereits geschlossene Incidents.

### 2. Incident-Grunddaten erfassen

Dokumentiere:

| Feld | Beobachtung |
|---|---|
| Incident Name |  |
| Severity |  |
| Status |  |
| Assigned to |  |
| Classification |  |
| Anzahl Alerts |  |
| Betroffene Geräte |  |
| Betroffene Benutzer |  |

### 3. Alerts im Incident prüfen

Öffne die Alert-Liste innerhalb des Incidents.

| Alert | Severity | Betroffenes Gerät | Kurze Beschreibung |
|---|---|---|---|
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

### 4. Evidence und Entities prüfen

Prüfe, welche Objekte mit dem Incident verbunden sind.

| Entity-Typ | Beispiele | Beobachtung |
|---|---|---|
| Device | Clientname |  |
| User | Benutzerkonto |  |
| File | Datei oder Hash |  |
| Process | Prozessname |  |
| IP / URL | Netzwerkziel |  |

### 5. Incident vs. Alert bewerten

Beantworte gemeinsam:

| Frage | Bewertung |
|---|---|
| Ist der Incident aus mehreren Alerts zusammengesetzt? |  |
| Gehören die Alerts wahrscheinlich zusammen? |  |
| Gibt es ein klares betroffenes Hauptgerät? |  |
| Gibt es einen Benutzerkontext? |  |
| Ist eine Eskalation nötig? |  |


## Bewertung im Betriebsalltag

| Beobachtung | Bedeutung |
|---|---|
| Ein Incident mit mehreren Alerts auf demselben Gerät | Wahrscheinlich zusammenhängende Angriffskette |
| Alerts auf mehreren Geräten | Mögliche Ausbreitung oder mehrere betroffene Systeme |
| High Severity + aktives Gerät | Schnellere Bewertung und ggf. Eskalation nötig |
| Kein betroffener Benutzer sichtbar | Weitere Kontextprüfung nötig |
| False Positive vermutet | Begründung und Evidence dokumentieren |

## Diskussionsfragen

- Warum sollte man nicht nur einen einzelnen Alert betrachten?
- Welche Informationen braucht die interne IT vom MSSP?
- Welche Informationen kann nur die interne IT liefern, z. B. Benutzer, Fachanwendung oder Gerätekritikalität?
- Wann wäre eine Response Action gerechtfertigt?
- Wann sollte ein Incident noch nicht geschlossen werden?

## Merksatz

Ein Alert ist ein Signal. Ein Incident ist der zusammenhängende Sicherheitsfall. Für die Bewertung im Betrieb sollte immer der Incident-Kontext betrachtet werden, nicht nur ein einzelner Alert.


---
---

# POWERSHELL

---

### 1. Lokalen Defender-Status prüfen

```powershell
Get-MpComputerStatus | Select-Object `
    AMRunningMode,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    AMServiceEnabled,
    IsTamperProtected,
    AntivirusSignatureVersion,
    AntivirusSignatureLastUpdated,
    NISEnabled,
    NISSignatureLastUpdated
```

---

### 2. Aktuelle Defender-Bedrohungserkennungen anzeigen

```powershell
Get-MpThreatDetection |
    Select-Object InitialDetectionTime, LastThreatStatusChangeTime, ThreatID, ThreatStatusID, Resources |
    Format-List
```

---

### 3. Aktive oder bekannte Threats anzeigen

```powershell
Get-MpThreat |
    Select-Object ThreatID, ThreatName, SeverityID, CategoryID, DidThreatExecute |
    Format-Table -AutoSize
```

---

### 4. Defender-Ereignisse der letzten 24 Stunden prüfen

```powershell
$StartTime = (Get-Date).AddHours(-24)

Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    StartTime = $StartTime
} |
Select-Object TimeCreated, Id, Message |
Format-List
```

---

### 5. ASR-Ereignisse im Incident-Zeitraum prüfen

```powershell
$StartTime = (Get-Date).AddHours(-24)

Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    Id = 1121,1122
    StartTime = $StartTime
} |
Select-Object TimeCreated, Id, Message |
Format-List
```

---
