# Session 2 - Übung 6
## Geeignete Response Action auswählen

## Praxissituation

Ein Gerät erzeugt einen Defender-Alert mit verdächtiger Aktivität. Der MSSP oder das Security-Team fragt die interne IT, ob das Gerät isoliert werden darf. Gleichzeitig ist unklar, ob der Benutzer gerade produktiv arbeitet oder ob das Gerät für einen kritischen Prozess benötigt wird.

Nach der MDE-Migration sind Response Actions wie `Run antivirus scan`, `Collect investigation package`, `Isolate device` oder `Restrict app execution` im Defender Portal verfügbar. Diese Aktionen sind hilfreich, können aber direkten Einfluss auf Benutzer und Betrieb haben.

## Ziel der Übung

Wir möchten typische Response Actions kennen, deren Auswirkungen einschätzen und entscheiden, welche Maßnahme in welchem Szenario angemessen ist.

## Benötigte Berechtigungen

- Leserechte im Microsoft Defender Portal
- Für echte Response Actions: entsprechende Defender-Rollen und Freigabe
- Für die Übung: keine produktiven Aktionen ohne explizite Genehmigung ausführen

## Wichtiger Hinweis

Diese Übung sollte primär als Entscheidungsübung durchgeführt werden. Produktive Aktionen wie `Isolate device` oder `Restrict app execution` dürfen nur auf Testgeräten oder nach klarer Freigabe ausgeführt werden.

## Ausgangspunkt

Portal:

```text
https://security.microsoft.com
```

Typische Pfade:

```text
Assets -> Devices -> <Gerät> -> Response actions
```

oder aus einem Incident/Alert heraus:

```text
Incident / Alert -> Device -> Response actions
```

## Aufgabe

Bewerte ein vorgegebenes Szenario und entscheide, welche Response Action passend wäre.

## Typische Response Actions

| Aktion | Bedeutung | Betriebswirkung |
|---|---|---|
| Run antivirus scan | Startet einen AV Scan auf dem Gerät | Geringer Eingriff, meist gut als erste Maßnahme |
| Collect investigation package | Sammelt Untersuchungsdaten vom Gerät | Geringer bis mittlerer Eingriff, hilfreich für Analyse |
| Isolate device | Trennt das Gerät weitgehend vom Netzwerk, Defender-Kommunikation bleibt möglich | Hoher Eingriff, kann Benutzerarbeit unterbrechen |
| Restrict app execution | Beschränkt die Ausführung nicht vertrauenswürdiger Anwendungen | Mittlerer bis hoher Eingriff, kann Anwendungen beeinflussen |
| Release from isolation | Hebt eine Geräteisolation wieder auf | Nur nach Bewertung und Freigabe |
| Manage tags | Setzt Tags zur Organisation oder Kennzeichnung | Kein direkter technischer Eingriff |

## Szenario A: Verdächtige Datei, keine aktive Ausbreitung

Beschreibung:

```text
Auf einem Client wurde eine verdächtige Datei erkannt. Es gibt keine Hinweise auf aktive laterale Bewegung. Der Benutzer arbeitet normal weiter.
```

Bewertung:

| Frage | Antwort |
|---|---|
| Ist das Gerät kritisch? |  |
| Gibt es aktive Folgeaktivitäten? |  |
| Gibt es weitere Alerts? |  |
| Ist der Benutzer erreichbar? |  |
| Welche Aktion ist angemessen? |  |

Mögliche Entscheidung:

```text
Run antivirus scan + weitere Timeline-Prüfung
```

## Szenario B: Verdacht auf aktive Kompromittierung

Beschreibung:

```text
Ein Gerät zeigt mehrere verdächtige Prozessketten, externe Netzwerkverbindungen und mögliche Credential-Theft-Aktivität.
```

Bewertung:

| Frage | Antwort |
|---|---|
| Gibt es Hinweise auf laufende Aktivität? |  |
| Besteht Risiko für andere Systeme? |  |
| Ist das Gerät geschäftskritisch? |  |
| Wer muss Freigabe geben? |  |
| Welche Aktion ist angemessen? |  |

Mögliche Entscheidung:

```text
Eskalation an Security/MSSP, Business Impact prüfen, danach ggf. Isolate device
```

## Szenario C: Analyse durch MSSP erforderlich

Beschreibung:

```text
Der MSSP benötigt weitere lokale Artefakte, um einen Alert zu bewerten. Es gibt noch keine klare Bestätigung einer Kompromittierung.
```

Mögliche Entscheidung:

```text
Collect investigation package
```

## Szenario D: Möglicher False Positive bei Fachanwendung

Beschreibung:

```text
Eine Fachanwendung erzeugt regelmäßig einen ASR- oder Defender-Alert. Der Fachbereich meldet, dass die Anwendung geschäftskritisch ist.
```

Mögliche Entscheidung:

```text
Keine sofortige Isolation. Evidence prüfen, App-Owner einbinden, ggf. Ausnahmeprozess starten.
```

## Entscheidungslogik

| Frage | Warum wichtig? |
|---|---|
| Ist die Aktivität noch aktiv? | Aktive Angriffe benötigen schnellere Reaktion |
| Gibt es Hinweise auf Ausbreitung? | Laterale Bewegung kann weitere Geräte betreffen |
| Ist das Gerät geschäftskritisch? | Isolation kann Betrieb stören |
| Ist der Benutzer erreichbar? | Kontext und Sofortmaßnahmen abstimmen |
| Gibt es eine Freigabe für Isolation? | Response Actions brauchen Governance |
| Hat der MSSP eine Empfehlung gegeben? | Externe Analyse berücksichtigen |
| Ist ein Ticket vorhanden? | Maßnahmen müssen dokumentiert werden |

## Ergebnis dokumentieren

| Feld | Eintrag |
|---|---|
| Gerät |  |
| Benutzer |  |
| Incident / Alert |  |
| Beobachtung |  |
| Risiko |  |
| Gewählte Aktion |  |
| Begründung |  |
| Freigabe durch |  |
| Ticketnummer |  |
| Nächster Schritt |  |

## Diskussionsfragen

- Wann ist ein AV Scan ausreichend?
- Wann ist Isolation gerechtfertigt?
- Wer darf Isolation freigeben?
- Welche Informationen benötigt der MSSP?
- Welche Response Actions darf die interne IT selbst ausführen?
- Wie wird eine Isolation wieder aufgehoben?

## Merksatz

Response Actions sind technische Maßnahmen mit betrieblicher Auswirkung. Die richtige Aktion hängt nicht nur vom Alert ab, sondern auch von Gerätetyp, Benutzer, Business Impact, Angriffskontext und Freigabeprozess.


---
---

# POWERSHELL

---

### 1. Defender-Status prüfen

```powershell
Get-MpComputerStatus | Select-Object `
    AMRunningMode,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    AMServiceEnabled,
    IsTamperProtected,
    FullScanAge,
    QuickScanAge,
    AntivirusSignatureLastUpdated
```

---

### 2. Quick Scan lokal starten

> In der Praxis sollte ein Scan im MDE-Betrieb bevorzugt zentral über das Defender Portal ausgelöst werden. Lokal ist dies für Test oder direkte Client-Prüfung möglich.

```powershell
Start-MpScan -ScanType QuickScan
```

---

### 3. Full Scan lokal starten

> Full Scans können lange dauern und Performance beeinflussen. Nicht unkontrolliert breit ausführen.

```powershell
Start-MpScan -ScanType FullScan
```

---

### 4. Scan-Status prüfen

```powershell
Get-MpComputerStatus | Select-Object `
    QuickScanStartTime,
    QuickScanEndTime,
    FullScanStartTime,
    FullScanEndTime,
    QuickScanAge,
    FullScanAge
```

---

### 5. Erkannte Bedrohungen anzeigen

```powershell
Get-MpThreatDetection |
    Select-Object InitialDetectionTime, LastThreatStatusChangeTime, ThreatID, ThreatStatusID, Resources |
    Format-List
```

---

### 6. Lokale Netzwerkverbindungen eines auffälligen Prozesses prüfen

```powershell
$ProcessName = "powershell"

$processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue

foreach ($p in $processes) {
    Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
            @{Name="ProcessName";Expression={$p.ProcessName}},
            @{Name="ProcessId";Expression={$p.Id}}
}
```