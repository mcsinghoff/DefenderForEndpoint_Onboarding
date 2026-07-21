# Session 4 – Übung 4
## Softwarebestand und CVE tenantweit untersuchen

## Praxissituation

Ein Hersteller meldet eine kritische Schwachstelle in einer Anwendung, die möglicherweise auf vielen Windows-11-Clients installiert ist. Die interne IT muss kurzfristig klären, welche Versionen im Tenant vorhanden sind, welche Geräte betroffen sind, ob öffentlicher Exploitcode existiert und welches Update empfohlen wird.

Dieser Betriebsfall tritt regelmäßig bei Browsern, PDF-Software, Runtimes, VPN-Clients, Management-Agents und Fachanwendungen auf.

## Ziel

Die Teilnehmer untersuchen ein Softwareprodukt oder eine konkrete CVE über Software Inventory, Vulnerability Management und Advanced Hunting.

## Voraussetzungen

- Leserechte auf Defender Vulnerability Management
- Zugriff auf Advanced Hunting (Erweiterte Suche)
- bekannte Testsoftware oder CVE für die Übung
- keine produktive Änderung erforderlich

## Schritt-für-Schritt-Anleitung

### 1. Software Inventory öffnen

Öffne:

```text
Exposure management (Risikoverwaltung)
-> Vulnerability management (Sicherheitsrisikoverwaltung)
-> Inventories (Bestände)
-> Software (Software)
```

Je nach Tenant kann der Bereich noch unter Endpoints (Endpunkte) sichtbar sein.

### 2. Nach dem Softwareprodukt suchen

Suche nach Hersteller oder Produktname. Öffne die Softwareseite und prüfe:

- Software vendor (Softwarehersteller)
- Software name (Softwarename)
- Version distribution (Versionsverteilung)
- exposed devices (gefährdete Geräte)
- weaknesses or vulnerabilities (Schwachstellen)
- end-of-support status (Status zum Supportende)
- security recommendations (Sicherheitsempfehlungen)

### 3. Versionsverteilung untersuchen

Prüfe, ob:

- mehrere Haupt- oder Patchversionen existieren,
- besonders alte Versionen noch aktiv sind,
- einzelne Geräte eine ungewöhnliche Version besitzen,
- die betroffene Version auf Pilot-, Admin- oder Spezialgeräten vorkommt.

### 4. Eine CVE öffnen

Öffne eine relevante CVE und prüfe:

- CVE identifier (CVE-Kennung)
- vulnerability severity (Schweregrad der Schwachstelle)
- CVSS score (CVSS-Bewertung)
- exploit available (Exploit verfügbar)
- published date (Veröffentlichungsdatum)
- vulnerability description (Beschreibung)
- affected software (betroffene Software)
- recommended security update (empfohlenes Sicherheitsupdate)
- CVE tags such as ZeroDay or NoSecurityUpdate (CVE-Markierungen wie ZeroDay oder NoSecurityUpdate)

### 5. Betroffene Geräte prüfen

Öffne die Geräteliste und kontrolliere:

- Anzahl betroffener Geräte,
- Gerätenamen und Gerätegruppen,
- OS-Version,
- Softwareversion,
- kritische oder privilegierte Geräte,
- Geräte, die bereits länger offline sind.

### 6. Software Evidence auf einem Beispielgerät prüfen

Öffne ein betroffenes Gerät:

```text
Assets (Bestand)
-> Devices (Geräte)
-> <Gerät>
-> Inventories (Bestände)
-> Software (Software)
```

Öffne den Softwareeintrag und prüfe den Software Evidence (Softwarenachweis), beispielsweise Registry- oder Dateisystemfundstellen.

### 7. Advanced Hunting: Versionen tenantweit zählen

```kql
let Product = 'SOFTWARE-NAME-HERE';
DeviceTvmSoftwareInventory
| where SoftwareName contains Product
| summarize Devices=dcount(DeviceId),
            DeviceNames=make_set(DeviceName, 20)
  by SoftwareVendor, SoftwareName, SoftwareVersion
| order by Devices desc
```

### 8. Advanced Hunting: Schwachstellen für das Produkt ausgeben

```kql
let Product = 'SOFTWARE-NAME-HERE';
DeviceTvmSoftwareVulnerabilities
| where SoftwareName contains Product
| summarize AffectedDevices=dcount(DeviceId),
            Devices=make_set(DeviceName, 20),
            Versions=make_set(SoftwareVersion, 20)
  by CveId, SoftwareVendor, SoftwareName,
     VulnerabilitySeverityLevel,
     RecommendedSecurityUpdate,
     RecommendedSecurityUpdateId
| order by AffectedDevices desc
```

### 9. Advanced Hunting: Exploit-Kontext ergänzen

```kql
let TargetCve = 'CVE-YYYY-NNNN';
DeviceTvmSoftwareVulnerabilities
| where CveId =~ TargetCve
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where CveId =~ TargetCve
    | project CveId, CvssScore, IsExploitAvailable,
              PublishedDate, VulnerabilityDescription
) on CveId
| project DeviceName, OSPlatform, OSVersion,
          SoftwareVendor, SoftwareName, SoftwareVersion,
          CveId, VulnerabilitySeverityLevel,
          CvssScore, IsExploitAvailable,
          RecommendedSecurityUpdate,
          RecommendedSecurityUpdateId
| order by DeviceName asc
```

### 10. Technische Maßnahme ableiten

Entscheide anhand der Ergebnisse, ob als nächster Schritt erforderlich ist:

- Softwareupdate,
- Deinstallation,
- Konfigurationsänderung,
- Pilot und gestaffelter Rollout,
- zusätzliche Härtung,
- temporäre Exception,
- Eskalation an App-Owner oder Hersteller.

## Kurze Zusammenfassung

Die Teilnehmer haben eine Software oder CVE vom Tenant-Überblick bis zum einzelnen Gerät untersucht. Sie können Versionsverteilung, betroffene Geräte, Exploit-Kontext, empfohlene Updates und Software Evidence zusammenführen und daraus einen konkreten nächsten Schritt ableiten.
