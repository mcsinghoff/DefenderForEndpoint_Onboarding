# Session 4 – Übung 3
## Security Recommendation risikobasiert priorisieren

## Praxissituation

Das Defender Portal zeigt zahlreiche Security Recommendations. Die IT-Leitung möchte wissen, welche drei Maßnahmen zuerst umgesetzt werden sollen. Einige Empfehlungen betreffen viele Standardclients, eine andere nur wenige privilegierte Geräte, und für eine dritte existiert bereits öffentlicher Exploitcode.

Eine reine Sortierung nach CVSS oder Geräteanzahl kann zu einer falschen Priorität führen. Die interne IT muss technische und geschäftliche Faktoren gemeinsam bewerten.

## Ziel

Die Teilnehmer vergleichen mehrere Sicherheitsempfehlungen und bestimmen eine nachvollziehbare Reihenfolge anhand von Bedrohung, Ausnutzbarkeit, Asset-Kritikalität, Scope und Umsetzungsaufwand.

## Voraussetzungen

- Leserechte im Microsoft Defender Portal
- Zugriff auf Defender Vulnerability Management
- Zugriff auf Security Recommendations und betroffene Geräte
- keine produktive Remediation erforderlich

## Schritt-für-Schritt-Anleitung

### 1. Recommendations öffnen

Öffne:

```text
https://security.microsoft.com

Exposure management (Risikoverwaltung)
-> Recommendations (Empfehlungen)
```

Je nach Tenant kann der Bereich unter:

```text
Endpoints (Endpunkte)
-> Vulnerability management (Sicherheitsrisikoverwaltung)
-> Recommendations (Empfehlungen)
```

erscheinen.

### 2. Drei unterschiedliche Empfehlungen auswählen

Wähle nach Möglichkeit:

- eine Empfehlung mit vielen betroffenen Geräten,
- eine Empfehlung mit hoher Bedrohungs- oder Exploit-Relevanz,
- eine Empfehlung mit wenigen, aber kritischen Geräten.

Verwende keine Empfehlung, bei der die Übung eine produktive Änderung erzwingen würde.

### 3. Details jeder Empfehlung öffnen

Prüfe:

- Recommendation name (Name der Empfehlung)
- related software or configuration (zugehörige Software oder Konfiguration)
- exposed devices (gefährdete Geräte)
- associated CVEs (zugehörige CVEs)
- threat insights (Bedrohungserkenntnisse)
- exploit availability (Exploit-Verfügbarkeit)
- security score impact (Auswirkung auf die Sicherheitsbewertung)
- remediation options (Wartungs-/Korrekturoptionen)
- existing exceptions (bestehende Ausnahmen)

### 4. Betroffene Geräte bewerten

Öffne die Liste der betroffenen Geräte und prüfe:

- Standardclient oder privilegiertes Admin-Gerät,
- normaler Benutzer oder kritische Rolle,
- Pilot-, Produktions- oder Sondergerät,
- externe Erreichbarkeit oder besondere Netzwerkposition,
- Anzahl und Verteilung der Geräte,
- bekannte Offline- oder Altgeräte.

Eine Empfehlung auf wenigen Admin-Geräten kann höher priorisiert sein als eine Empfehlung auf vielen wenig kritischen Clients.

### 5. Threat- und Exploit-Kontext prüfen

Achte auf Hinweise wie:

- Active alert (Aktive Warnung),
- Active campaign (Aktive Kampagne),
- Exploit available (Exploit verfügbar),
- Zero-day (Zero-Day),
- No security update (Kein Sicherheitsupdate verfügbar),
- erhöhte EPSS-Wahrscheinlichkeit.

Öffne bei Bedarf den zugehörigen Threat-Analytics- oder CVE-Kontext.

### 6. Umsetzungsaufwand berücksichtigen

Bewerte, ob die Maßnahme:

- direkt über Intune aktualisiert werden kann,
- einen App-Owner-Test benötigt,
- ein Betriebssystem- oder Browserupdate verlangt,
- eine Fachanwendung beeinträchtigen kann,
- eine Deinstallation erfordert,
- bereits durch einen laufenden Change abgedeckt ist.

### 7. Prioritätsreihenfolge bilden

Eine sinnvolle Reihenfolge folgt typischerweise diesem Muster:

```text
1. aktiv ausgenutzt + kritische Assets + verfügbare Abhilfe
2. öffentlicher Exploit + größere Exposition + vertretbarer Rolloutaufwand
3. hohe technische Schwere ohne aktive Ausnutzung
4. reine Score-Verbesserung ohne aktuellen Threat-Kontext
```

Die Reihenfolge ist zu begründen; sie darf nicht ausschließlich aus dem Portalranking übernommen werden.

### 8. Nächsten Prozess festlegen

Für die priorisierte Empfehlung wird entschieden zwischen:

- Remediation Request (Wartungsanforderung),
- zusätzlichem App-Owner-Test,
- Pilot-Deployment,
- Exception (Ausnahme),
- weiterer Threat- oder Scope-Analyse.

## Kurze Zusammenfassung

Die Teilnehmer haben Security Recommendations nicht nur nach technischer Schwere, sondern anhand von Exploit-Kontext, kritischen Assets, betroffenen Geräten, Business-Abhängigkeit und Umsetzungsaufwand priorisiert. Daraus kann ein nachvollziehbarer Remediation-Backlog entstehen.
