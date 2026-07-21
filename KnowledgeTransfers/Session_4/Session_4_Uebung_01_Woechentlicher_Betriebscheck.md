# Session 4 – Übung 1
## Wöchentlichen Betriebs- und Policy-Health-Check durchführen

## Praxissituation

Nach der Migration von Trellix auf Microsoft Defender for Endpoint soll die interne IT jeden Montag prüfen, ob im Security-Betrieb offene technische Probleme oder überfällige Aufgaben bestehen.

Am vorherigen Wochenende wurden Intune-Richtlinien geändert und mehrere Geräte waren längere Zeit offline. Gleichzeitig sind neue Security Recommendations und eine aktuelle Threat-Analytics-Meldung erschienen. Das Team benötigt deshalb einen wiederholbaren Überblick, bevor einzelne Probleme an Client-Team, App-Owner oder MSSP weitergegeben werden.

## Ziel

Die Teilnehmer führen einen kompakten wöchentlichen Betriebscheck über Microsoft Defender XDR und Microsoft Intune durch. Dabei werden Policy-Fehler, offene Security Tasks, priorisierte Risiken, Wartungsaktivitäten und aktuelle Threat-Informationen geprüft.

## Voraussetzungen

- Leserechte im Microsoft Defender Portal
- Leserechte im Microsoft Intune Admin Center
- Zugriff auf Endpoint Security Reports (Endpunktsicherheitsberichte)
- Zugriff auf Vulnerability Management (Sicherheitsrisikoverwaltung)
- keine produktiven Änderungen erforderlich

## Schritt-für-Schritt-Anleitung

### 1. Intune Endpoint Security Dashboard öffnen

Öffne:

```text
https://intune.microsoft.com

Endpoint security (Endpunktsicherheit)
-> Overview (Übersicht)
```

Prüfe, ob das Dashboard auf folgende Bereiche hinweist:

- Policy deployment errors (Richtlinienbereitstellungsfehler)
- Security task status (Status von Sicherheitsaufgaben)
- Microsoft Defender for Endpoint connector status (Connectorstatus von Microsoft Defender for Endpoint)
- auffällige oder nicht konforme Gerätezustände

Öffne nur die Bereiche, für die ein Fehler, ein ungewöhnlicher Trend oder eine offene Aufgabe sichtbar ist.


### 2. Intune Security Tasks prüfen

Öffne je nach aktueller Portalnavigation:

```text
Endpoint security (Endpunktsicherheit)
-> Security tasks (Sicherheitsaufgaben)
```

Prüfe:

- neue Aufgaben aus Defender Vulnerability Management,
- Accepted (Akzeptiert), In progress (In Bearbeitung) oder Completed (Abgeschlossen),
- Fälligkeit,
- betroffene Geräte,
- verantwortliches Team,
- Aufgaben ohne Owner oder Fortschritt.

Eine Security Task ist ein Arbeitsauftrag. Sie beweist noch nicht, dass das Risiko bereits behoben wurde.

### 3. Offene Wartungsaktivitäten im Defender Portal prüfen

Öffne:

```text
https://security.microsoft.com

Exposure management (Gefährdungsverwaltung)
-> Vulnerability management (Verwaltung von Sicherheitsrisiken)
-> Remediation (Wartung/Korrektur)
```

Je nach Tenant kann der Bereich unter einer älteren Endpoints-Navigation erscheinen.

Prüfe:

- offene Remediation Activities (Wartungsaktivitäten),
- überfällige Maßnahmen,
- verbleibende betroffene Geräte,
- Maßnahmen, die laut IT abgeschlossen sind, aber noch keine Risikoreduktion zeigen,
- Ausnahmen mit nahendem Ablaufdatum.

### 5. Top Security Recommendations prüfen

Öffne:

```text
Exposure management (Risikoverwaltung)
-> Recommendations (Empfehlungen)
```

Sortiere nach der im Portal angebotenen Risikopriorität. Öffne die wichtigsten neuen oder stark veränderten Empfehlungen und prüfe:

- Number of exposed devices (Anzahl gefährdeter Geräte)
- Threat insights (Bedrohungserkenntnisse)
- Exploit availability (Exploit-Verfügbarkeit)
- betroffene kritische Ressourcen
- verfügbare Remediation (Wartung/Korrektur)
- bereits bestehende Exceptions (Ausnahmen)

### 6. Threat Analytics prüfen

Öffne:

```text
Threat intelligence (Bedrohungsinformationen)
-> Threat analytics (Bedrohungsanalyse)
```

Konzentriere dich auf:

- Latest threats (Neueste Bedrohungen)
- High-impact threats (Bedrohungen mit hohen Auswirkungen)
- Highest exposure threats (Bedrohungen mit der höchsten Exposition)

Öffne mindestens einen neuen oder tenantrelevanten Bericht und prüfe, ob Incidents, betroffene Ressourcen oder Endpunktexposition angezeigt werden.

### 7. Betriebscheck abschließen

Der Check ist abgeschlossen, wenn für jede relevante Abweichung ein nächster Schritt existiert, zum Beispiel:

- technische Analyse durch das Client-Team,
- App-Owner-Prüfung,
- Eskalation an Security oder MSSP,
- Remediation Request,
- zeitlich begrenzte Exception,
- erneute Prüfung nach dem nächsten Gerätesync.

## Kurze Zusammenfassung

Die Teilnehmer haben einen wiederholbaren wöchentlichen Betriebscheck durchgeführt. Sie haben Policy Errors, offene Security Tasks, Wartungsaktivitäten, priorisierte Sicherheitsempfehlungen und aktuelle Threat-Analytics-Berichte geprüft und können daraus konkrete Folgeaktionen ableiten.
