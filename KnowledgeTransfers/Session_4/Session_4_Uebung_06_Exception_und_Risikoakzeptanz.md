# Session 4 – Übung 6
## Exception und Risikoakzeptanz kontrolliert bewerten

## Praxissituation

Eine geschäftskritische Fachanwendung enthält eine bekannte Schwachstelle. Der Hersteller stellt ein kompatibles Update jedoch erst in sechs Wochen bereit. Eine sofortige Deinstallation würde einen wichtigen Geschäftsprozess unterbrechen.

Der Fachbereich fordert deshalb, die Security Recommendation dauerhaft auszublenden. Im Betrieb wäre das riskant: Eine Ausnahme ohne Ablaufdatum, Owner oder Kompensationsmaßnahmen kann über Jahre bestehen bleiben.

## Ziel

Die Teilnehmer bewerten, wann eine Exception vertretbar ist, wie der technische Scope begrenzt wird und welche Governance- und Kompensationsmaßnahmen erforderlich sind.

## Voraussetzungen

- Leserechte auf Defender Vulnerability Management
- Kenntnis eines geeigneten Beispielrisikos
- Zugriff auf den internen Risk-/Change-Prozess
- keine produktive Ausnahme ohne Genehmigung

## Schritt-für-Schritt-Anleitung

### 1. Empfehlung und Risiko öffnen

Navigiere zu:

```text
Exposure management (Risikoverwaltung)
-> Recommendations (Empfehlungen)
-> <Sicherheitsempfehlung>
```

Prüfe:

- technisches Risiko,
- zugehörige CVEs,
- Exploit-Verfügbarkeit,
- betroffene Geräte,
- verfügbare Updates oder Alternativen,
- vorhandene Threat Insights (Bedrohungserkenntnisse).

### 2. Business-Begründung validieren

Eine Ausnahme ist nur vertretbar, wenn eine konkrete und überprüfbare Begründung existiert, zum Beispiel:

- Herstellerupdate noch nicht verfügbar,
- regulatorisch notwendige Altanwendung,
- Update verursacht bestätigten Produktionsausfall,
- Hardware-/Software-Abhängigkeit verhindert sofortige Umstellung.

Nicht ausreichend sind allgemeine Aussagen wie:

```text
Die Anwendung ist wichtig.
Das Update könnte Probleme machen.
Wir haben aktuell keine Zeit.
```

### 3. Scope minimieren

Prüfe, ob die Ausnahme auf folgende Weise eingeschränkt werden kann:

- nur betroffene Software,
- nur konkrete Version,
- nur definierte Gerätegruppe,
- nur einzelne Spezialgeräte,
- keine Standardclients,
- keine privilegierten Admin-Geräte, sofern vermeidbar.

Eine partielle Ausnahme ist einer tenantweiten Ausnahme vorzuziehen.

### 4. Kompensationsmaßnahmen festlegen

Wähle passende Maßnahmen, beispielsweise:

- Netzwerkkommunikation auf notwendige Ziele beschränken,
- Anwendung nicht aus dem Internet erreichbar machen,
- lokale Administratorrechte entfernen,
- ASR- oder Firewall-Schutz verstärken,
- Nutzung auf wenige Geräte begrenzen,
- verstärktes Monitoring über Advanced Hunting oder Custom Detection,
- tägliche Backups und Wiederherstellung testen,
- Benutzer über erhöhte Vorsicht informieren,
- Ersatz- oder Migrationsprojekt beschleunigen.

### 5. Owner und Laufzeit definieren

Jede Ausnahme benötigt:

- Risk Owner (Risikoverantwortlicher),
- App-Owner,
- technische Kontaktperson,
- Startdatum,
- Ablaufdatum,
- Review-Datum,
- Exit-Plan,
- Ticket- oder Change-Referenz.

Das Ablaufdatum darf nicht lediglich durch eine spätere manuelle Erinnerung ersetzt werden.

### 6. Exception im Portal vorbereiten

Je nach Portalversion befindet sich die Funktion im Bereich der Security Recommendation oder unter Exceptions (Ausnahmen).

Wähle sinngemäß:

```text
Create exception (Ausnahme erstellen)
```

Konfiguriere:

- vollständige oder partielle Ausnahme,
- betroffene Gerätegruppe,
- Begründung,
- Laufzeit,
- Notizen und Referenzen.

In der Schulung wird vor der endgültigen produktiven Bestätigung abgebrochen, sofern keine Freigabe vorliegt.

### 7. Technisches Monitoring für die Ausnahme definieren

Beispielquery für Geräte mit einer konkreten verwundbaren Software:

```kql
let Product = 'SOFTWARE-NAME-HERE';
DeviceTvmSoftwareVulnerabilities
| where SoftwareName contains Product
| summarize Vulnerabilities=dcount(CveId),
            Cves=make_set(CveId, 50),
            Versions=make_set(SoftwareVersion, 20)
  by DeviceName
| order by Vulnerabilities desc
```

Beispielquery für eine konkrete CVE:

```kql
let TargetCve = 'CVE-YYYY-NNNN';
DeviceTvmSoftwareVulnerabilities
| where CveId =~ TargetCve
| project DeviceName, OSPlatform, SoftwareVendor,
          SoftwareName, SoftwareVersion,
          VulnerabilitySeverityLevel,
          RecommendedSecurityUpdate
| order by DeviceName asc
```

### 8. Review- und Exit-Prozess festlegen

Beim Review wird geprüft:

- Ist ein Herstellerupdate verfügbar?
- Ist die Anzahl betroffener Geräte gleich geblieben oder gestiegen?
- Haben sich Exploit- oder Threat-Informationen verändert?
- Sind Kompensationsmaßnahmen weiterhin aktiv?
- Kann die Anwendung ersetzt oder isoliert werden?
- Muss die Ausnahme beendet oder formell verlängert werden?

Eine Verlängerung ist eine neue Risikoentscheidung und keine automatische Formalität.

## Kurze Zusammenfassung

Die Teilnehmer haben eine Ausnahme als kontrollierte Risikoentscheidung behandelt. Sie haben den Scope begrenzt, Business-Begründung, Owner, Ablaufdatum, Exit-Plan und kompensierende Maßnahmen definiert und verstehen, dass eine Exception niemals eine dauerhafte Ersatzlösung für Remediation ist.
