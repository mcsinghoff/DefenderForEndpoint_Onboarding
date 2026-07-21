# Session 4 – Übung 7
## Threat Analytics auswerten und einen Betriebsbericht ableiten

## Praxissituation

Microsoft veröffentlicht einen neuen Bericht zu einer aktiv ausgenutzten Schwachstelle oder einer Ransomware-Kampagne. Das MSSP weist auf den Bericht hin und fragt, ob der Kunde bereits betroffen oder exponiert ist.

Die interne IT muss den Bericht nicht nur lesen, sondern auf den eigenen Tenant übertragen und eine klare Information für Security, Client-Team und Management erstellen.

## Ziel

Die Teilnehmer prüfen einen Threat-Analytics-Bericht, bewerten tenantbezogene Incidents, Exposition und empfohlene Maßnahmen und leiten daraus einen kompakten Betriebsbericht ab.

## Voraussetzungen

- Zugriff auf Threat Analytics im Microsoft Defender Portal
- Leserechte auf Incidents, betroffene Assets und Vulnerability-Informationen
- Zugriff auf Intune für mögliche Folgeprüfungen
- keine produktive Änderung erforderlich

## Schritt-für-Schritt-Anleitung

### 1. Threat Analytics öffnen

Navigiere zu:

```text
https://security.microsoft.com

Threat intelligence (Bedrohungsinformationen)
-> Threat analytics (Bedrohungsanalyse)
```

### 2. Relevanten Bericht auswählen

Prüfe die Bereiche:

- Latest threats (Neueste Bedrohungen)
- High-impact threats (Bedrohungen mit hohen Auswirkungen)
- Highest exposure threats (Bedrohungen mit der höchsten Exposition)

Wähle einen Bericht, der:

- neu oder kürzlich aktualisiert ist,
- Endpoints oder Windows-Software betrifft,
- aktive Warnungen oder Exposition im Tenant zeigt,
- eine konkrete Schutz- oder Patchmaßnahme enthält.

### 3. Executive Summary lesen

Lies die Zusammenfassung und identifiziere:

- Threat Actor oder Kampagne,
- betroffene Produkte,
- typische Initial-Access- oder Angriffstechniken,
- mögliche Auswirkungen,
- bekannte Indicators of Compromise,
- Veröffentlichungs- und Aktualisierungsdatum.

### 4. Tenant-Auswirkung prüfen

Öffne die tenantbezogenen Abschnitte und prüfe:

- Related incidents (Zugehörige Incidents)
- Active alerts (Aktive Warnungen)
- Resolved alerts (Behobene Warnungen)
- Impacted assets (Betroffene Ressourcen)
- Endpoint exposure (Endpunktexposition)
- Recommended actions (Empfohlene Maßnahmen)

Unterscheide:

```text
bereits angegriffen
vs.
verwundbar/exponiert
vs.
geschützt/nicht betroffen
```

### 5. Betroffene Software oder CVE weiter untersuchen

Wenn der Bericht eine konkrete Schwachstelle nennt, öffne:

```text
Exposure management (Risikoverwaltung)
-> Vulnerability management (Sicherheitsrisikoverwaltung)
-> Weaknesses (Schwachstellen)
```

oder suche die CVE über Software Inventory und Advanced Hunting.

Beispielquery:

```kql
let TargetCve = 'CVE-YYYY-NNNN';
DeviceTvmSoftwareVulnerabilities
| where CveId =~ TargetCve
| summarize AffectedDevices=dcount(DeviceId),
            Devices=make_set(DeviceName, 50),
            Versions=make_set(SoftwareVersion, 20)
  by SoftwareVendor, SoftwareName,
     VulnerabilitySeverityLevel,
     RecommendedSecurityUpdate,
     RecommendedSecurityUpdateId
```

### 6. Vorhandene Schutzmaßnahmen bewerten

Prüfe, welche Schutzmaßnahmen bereits aktiv sind, zum Beispiel:

- Defender Antivirus und Cloud Protection,
- relevante ASR-Regeln,
- Network Protection,
- aktuelle Security Intelligence,
- verfügbare Updates,
- Intune-Härtungsrichtlinien,
- MSSP-Monitoring oder Custom Detections.

Nicht jede Empfehlung aus einem globalen Bericht ist automatisch im Kundenkontext identisch umzusetzen.

### 7. Maßnahmen nach Dringlichkeit ordnen

Verwende eine einfache Reihenfolge:

```text
Sofort:
aktive Incidents, bestätigte Treffer, Credential- oder Ausbreitungsrisiko

Kurzfristig:
exponierte Geräte, Exploit verfügbar, Update vorhanden

Geplant:
Härtung, zusätzliche Detection, langfristige Softwareablösung
```

### 8. Kompakten Betriebsbericht erstellen

Der Bericht sollte enthalten:

```text
Titel und Datum des Threat-Analytics-Berichts

Tenant-Relevanz:
- aktive Incidents oder Alerts
- betroffene beziehungsweise exponierte Geräte
- betroffene Software/CVEs

Aktueller Schutzstatus:
- vorhandene Defender-/Intune-Kontrollen
- verfügbare Updates oder Remediations

Empfohlene Maßnahmen:
- Sofortmaßnahmen
- kurzfristige Maßnahmen
- geplante Verbesserungen

Owner und Fristen:
- Security/MSSP
- Client-Team
- App-Owner
- Management/Risk Owner
```

### 9. Folgeaktionen in die Betriebsprozesse überführen

Je nach Ergebnis:

- Incident oder Alert an MSSP eskalieren,
- Remediation Request erstellen,
- Intune-Update oder Policy-Change planen,
- App-Owner kontaktieren,
- zeitlich begrenzte Exception prüfen,
- Custom Detection oder Hunting Query ergänzen,
- Management informieren.

## Kurze Zusammenfassung

Die Teilnehmer haben einen aktuellen Threat-Analytics-Bericht auf den eigenen Tenant übertragen. Sie können zwischen aktivem Angriff und reiner Exposition unterscheiden, betroffene Software und Geräte prüfen, vorhandene Kontrollen bewerten und daraus einen verständlichen Betriebsbericht mit Ownern und Fristen ableiten.
