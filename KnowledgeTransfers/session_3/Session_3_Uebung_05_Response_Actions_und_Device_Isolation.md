# Session 3 - Übung 5
## Response Actions auswählen und Device Isolation bewerten

## Praxissituation

Ein Windows-11-Notebook zeigt verdächtige PowerShell-Aktivität und Verbindungen zu einer unbekannten externen IP-Adresse. Das MSSP empfiehlt die sofortige Isolation. Der Benutzer arbeitet jedoch in einer geschäftskritischen Abteilung und nimmt gerade an einem wichtigen Termin teil.

Die interne IT muss eine schnelle, nachvollziehbare Entscheidung zwischen Sicherheitsrisiko und Business Impact treffen.

## Ziel der Übung

Die Teilnehmer sollen geeignete Response Actions auswählen, die Voraussetzungen einer Isolation prüfen und einen Freigabe- sowie Kommunikationsprozess dokumentieren.

## Benötigte Berechtigungen

- Leserechte auf Device Page, Incident und Action Center
- Für echte Aktionen: Rolle für Active Remediation Actions und Zugriff auf die betreffende Device Group
- Kein produktives Isolieren ohne ausdrückliche Freigabe

## Aufgabe

Bewerte das Szenario und entscheide zwischen:

- Antivirus Scan,
- Automated Investigation,
- Investigation Package,
- Restrict App Execution,
- Device Isolation,
- Live Response,
- Eskalation ohne direkte Aktion.

## Response-Action-Matrix

| Aktion | Geeignet, wenn | Nicht ausreichend oder riskant, wenn |
|---|---|---|
| Quick/Full AV Scan | Verdächtige Datei, keine aktive Ausbreitung | Aktive C2-, Credential- oder Lateral-Movement-Hinweise |
| Automated Investigation | Weitere automatische Analyse sinnvoll | Sofortige Eindämmung erforderlich |
| Investigation Package | Artefakte für MSSP/Forensik benötigt | Aktiver Angriff muss zuerst eingedämmt werden |
| Restrict App Execution | Nicht vertrauenswürdige App-Ausführung stoppen | Geschäftsanwendungen könnten betroffen sein |
| Isolate Device | Aktive Kompromittierung oder Ausbreitungsrisiko | Business Impact muss bewertet werden, verhindert aber nicht jede lokale Aktivität |
| Live Response | Tiefe Echtzeitanalyse erforderlich | Fehlende Freigabe oder unzureichende Rollen/Governance |

## Schritt-für-Schritt-Anleitung

### 1. Aktive Gefahr bewerten

| Prüffrage | Beobachtung |
|---|---|
| Gibt es laufende verdächtige Prozesse? |  |
| Gibt es aktive externe Verbindungen? |  |
| Hinweise auf Credential Theft? |  |
| Hinweise auf laterale Bewegung? |  |
| Weitere betroffene Geräte? |  |
| Wurde die Aktivität bereits blockiert? |  |

### 2. Business Impact bewerten

| Prüffrage | Beobachtung |
|---|---|
| Benutzerrolle |  |
| Kritischer Fachprozess |  |
| Ersatzgerät verfügbar |  |
| Remote-/VPN-Nutzung |  |
| Datenverlust bei sofortiger Unterbrechung |  |
| Ansprechpartner erreichbar |  |

### 3. Technische Voraussetzungen prüfen

- Gerät ist in MDE aktiv und erreichbar.
- Sense Sensor ist funktionsfähig.
- Benutzer verfügt über erforderliche Defender-Rolle.
- Zugriff auf die Device Group ist vorhanden.
- Proxy- und VPN-Besonderheiten sind bekannt.
- Ticket und Freigabeprozess sind vorbereitet.

### 4. Entscheidung treffen

| Risikobild | Empfohlene Reaktion |
|---|---|
| Einzelne Datei, keine Folgeaktivität | Scan und Timeline-Prüfung |
| Unklare Lage, keine aktive Ausbreitung | Investigation Package oder AIR |
| Aktive externe Kommunikation | Isolation ernsthaft prüfen |
| Credential Theft/Lateral Movement | Sofortige Security-Eskalation und Isolation |
| Wahrscheinlicher False Positive | Keine vorschnelle Isolation; Owner einbinden |

### 5. Isolation im Portal nachvollziehen

Nur auf einem freigegebenen Testgerät oder als Demonstration:

```text
Assets -> Devices -> <Gerät> -> Isolate device
```

Vor Bestätigung:

- Isolationstyp prüfen, falls mehrere Optionen angeboten werden,
- aussagekräftigen Kommentar eintragen,
- Ticketnummer angeben,
- Benutzerkommunikation vorbereiten.

Beispielkommentar:

```text
Isolation aufgrund aktiver verdächtiger PowerShell- und Netzwerkaktivität.
Freigabe durch <Rolle/Name>, Ticket <Nummer>.
Weitere Untersuchung durch MSSP/Security läuft.
```

### 6. Status nachverfolgen

Prüfe:

- Action Center,
- Device Timeline,
- Device Status,
- Zeitpunkt und ausführende Person,
- erfolgreiche oder fehlgeschlagene Umsetzung.

### 7. Aufhebung planen

Eine Isolation wird erst aufgehoben, wenn:

- aktive Bedrohung beendet ist,
- Remediation erfolgreich war,
- Zugangsdaten bei Bedarf zurückgesetzt wurden,
- Rebuild oder Bereinigung validiert wurde,
- Security/MSSP die Freigabe erteilt hat,
- Ticket und Incident aktualisiert sind.

## KQL-Ergänzung

Aktive oder kürzlich beobachtete Netzwerkverbindungen eines Geräts:

```kql
let DeviceToCheck = "DEVICE-NAME-HERE";
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName =~ DeviceToCheck
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort,
          RemoteUrl, Protocol, ActionType
| order by Timestamp desc
```

Mehrere Geräte mit derselben Remote-IP suchen:

```kql
let TargetIP = "203.0.113.10";
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == TargetIP
| summarize Connections=count(),
            FirstSeen=min(Timestamp),
            LastSeen=max(Timestamp),
            Processes=make_set(InitiatingProcessFileName, 20)
  by DeviceName
| order by Connections desc
```

## PowerShell-Ergänzung

Lokalen Schutzstatus prüfen:

```powershell
Get-MpComputerStatus | Select-Object `
    AMRunningMode,
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    IsTamperProtected,
    QuickScanAge,
    FullScanAge,
    AntivirusSignatureLastUpdated
```

Aktuelle TCP-Verbindungen eines Prozesses prüfen:

```powershell
$ProcessName = 'powershell'
Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | ForEach-Object {
    $Process = $_
    Get-NetTCPConnection -OwningProcess $Process.Id -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
            State, @{Name='ProcessName';Expression={$Process.ProcessName}},
            @{Name='ProcessId';Expression={$Process.Id}}
}
```

> Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.

## Erwartetes Ergebnis

| Feld | Entscheidung |
|---|---|
| Gewählte Response Action |  |
| Sicherheitsbegründung |  |
| Business Impact |  |
| Freigabe |  |
| Benutzerkommunikation |  |
| Technische Validierung |  |
| Bedingung für Aufhebung |  |

## Diskussionsfragen

- Wann ist ein AV Scan ausreichend?
- Wann ist Isolation trotz Business Impact zwingend?
- Wer besitzt die Freigabekompetenz außerhalb der Geschäftszeiten?
- Was passiert, wenn ein isoliertes Gerät hinter Full-Tunnel-VPN den Defender-Dienst nicht mehr erreicht?
- Welche Maßnahmen sind nach Credential Theft zusätzlich nötig?

## Merksatz

Device Isolation ist eine Containment-Maßnahme mit hoher Wirkung. Sie muss bei aktiver Gefahr schnell, aber mit klarer Freigabe, Dokumentation und Aufhebungsbedingung eingesetzt werden.
