# Knowledge Transfer Session 2  
## ASR, Incidents, Alerts und Device Investigation

## Ziel der Session

Die Teilnehmer sollen verstehen, wie Microsoft Defender for Endpoint nach der Migration hilft, typische Angriffstechniken zu erkennen, zu verhindern und zu untersuchen.

Der Fokus liegt auf:

- Attack Surface Reduction Regeln
- ASR-Modi: Disabled, Audit, Warn, Block
- ASR-Auswertung und Tuning
- Incidents und Alerts im Microsoft Defender Portal
- Device Investigation über Device Page und Timeline
- erste Bewertung von Evidence, Entities und Prozessketten
- Response Actions und Eskalationsgrenzen
- Zusammenspiel zwischen interner IT und ggf. MSSP/SOC

Diese Session ist keine vollständige SOC-Schulung. Ziel ist, dass die interne IT nach der Migration die wichtigsten MDE-Sicherheitsmeldungen, ASR-Ereignisse und Geräteuntersuchungen einordnen kann.

---

## Typische Angriffsszenarien

| Szenario | Beispiel | Relevante Schutz- oder Untersuchungsfunktion |
|---|---|---|
| Office startet PowerShell | Benutzer öffnet ein präpariertes Word-Dokument, das PowerShell startet | ASR Office Child Process Rule, Alert, Device Timeline |
| Skript lädt Malware nach | JavaScript oder VBScript lädt eine EXE aus dem Internet herunter und startet sie | ASR Script Rules, Defender AV, Cloud Protection |
| Credential Dumping | Tool versucht, LSASS-Speicher auszulesen | ASR LSASS Rule, Alert, Incident, Device Investigation |
| Laterale Bewegung | Angreifer startet Prozesse remote über WMI oder PSExec | ASR Lateral Movement Rule, Device Timeline, Incident |
| Ransomware-Verhalten | Prozess zeigt ransomware-typische Dateiaktivitäten | ASR Ransomware Rule, Defender AV, Incident |
| USB-Ausführung | Unsignierte Anwendung wird von USB-Stick gestartet | ASR USB Rule, Device Timeline |
| False Positive bei Fachanwendung | Legitimes Tool wird von ASR im Audit oder Block Mode erkannt | ASR Report, App-Owner-Review, gezielte Ausnahme |
| Verdächtiger Prozessbaum | Outlook oder Word startet Script Host, PowerShell oder cmd.exe | Alert Story, Device Timeline, Prozesskette |

---

## Investigation-Grundlogik

| Schritt | Leitfrage |
|---:|---|
| 1 | Was wurde erkannt? |
| 2 | Welches Gerät ist betroffen? |
| 3 | Welcher Benutzer war angemeldet oder beteiligt? |
| 4 | Welche Datei, welcher Prozess oder welche URL ist relevant? |
| 5 | Was ist vor dem Alert passiert? |
| 6 | Was ist nach dem Alert passiert? |
| 7 | Gibt es weitere betroffene Geräte oder Benutzer? |
| 8 | Ist das Verhalten legitim, verdächtig oder klar bösartig? |
| 9 | Muss sofort reagiert werden? |
| 10 | Wer muss eingebunden werden: interne IT, Security, MSSP, Fachbereich, Datenschutz? |

---

## Entscheidungsbeispiele für Response Actions

| Situation | Mögliche Aktion | Hinweis |
|---|---|---|
| Verdächtige Datei, aber Gerät arbeitet normal | Antivirus Scan starten | Niedriger Eingriff, gute erste Maßnahme |
| Verdacht auf aktive Kompromittierung | Gerät isolieren | Hoher Eingriff, Business Impact prüfen |
| Weitere technische Analyse nötig | Investigation Package sammeln | Sinnvoll für Security-Team oder MSSP |
| Verdächtige App-Ausführung stoppen | App-Ausführung einschränken | Vorher Auswirkungen auf Benutzer prüfen |
| False Positive wahrscheinlich | Nicht sofort isolieren; Evidence prüfen | App-Owner oder Fachbereich einbeziehen |
| Kritischer Benutzer oder Produktionssystem betroffen | Eskalation vor Response Action | Business Impact muss bewertet werden |
| MSSP meldet Incident | Interne IT liefert Geräte-, Benutzer- und Anwendungskontext | Zusammenarbeit klar dokumentieren |
| Maßnahme abgeschlossen | Ticket und Incident aktualisieren | Entscheidung und Begründung dokumentieren |

---

## Vokabelliste

| Begriff | Kurzbeschreibung |
|---|---|
| ASR | Attack Surface Reduction; Regeln zur Reduzierung typischer Angriffstechniken |
| Attack Surface | Gesamtheit möglicher Angriffswege auf Geräte, Benutzer und Anwendungen |
| ASR Rule | Einzelne Regel, die bestimmtes riskantes Verhalten blockiert oder auditiert |
| Audit Mode | Ereignis wird protokolliert, aber nicht blockiert |
| Warn Mode | Benutzer wird gewarnt und kann je nach Regel eventuell fortfahren |
| Block Mode | Verhalten wird blockiert |
| ASR Exclusion | Ausnahme für ASR-Regeln, z. B. für legitime Anwendung |
| Defender Antivirus | *Lokale* AV-Schutzkomponente auf dem Windows-Client |
| MDE | Microsoft Defender for Endpoint |
| EDR | Endpoint Detection and Response; Erkennung, Untersuchung und Reaktion auf Endpoint-Ereignisse |
| Incident | Zusammenhängender Sicherheitsfall aus Alerts, Entities und Evidence |
| Alert | Einzelne Erkennung oder verdächtige Aktivität (Nicht zwingend mit Handlungsbedarf) |
| Alert Story | Darstellung des Ablaufs und Kontextes eines Alerts |
| Evidence | Relevante Objekte wie Datei, Prozess, Gerät, Benutzer, IP oder URL |
| Entity | Sicherheitsrelevantes Objekt im Incident-Kontext |
| Affected Asset | Betroffenes Gerät, Benutzerkonto oder anderes Asset |
| Severity | Kritikalität eines Alerts oder Incidents (Informational, Low, Medium, High) |
| Status | Bearbeitungsstand, z. B. New, In progress oder Resolved |
| Classification | Bewertungsergebnis, z. B. True Positive oder False Positive |
| Assignment | Zuweisung eines Incidents oder Alerts an eine Person oder ein Team |
| Device Page | Geräteansicht im Defender Portal |
| Device Timeline | Zeitliche Ereignisansicht eines Geräts |
| Process Tree | Darstellung, welcher Prozess welchen anderen Prozess gestartet hat |
| Initiating Process | Prozess, der eine Aktion ausgelöst hat |
| File Hash | Eindeutiger kryptografischer Fingerabdruck einer Datei, z. B. SHA-256 |
| URL | Webadresse, die in Alerts oder Evidence relevant sein kann |
| IP Address | Netzwerkadresse, die in Kommunikation oder Alerts auftauchen kann |
| User Context | Benutzerkontext einer Aktivität oder Anmeldung |
| Response Action | Aktion aus dem Defender Portal zur Reaktion auf ein Gerät oder eine Bedrohung |
| Isolate Device | Gerät vom Netzwerk isolieren, mit Ausnahmen für Defender-Kommunikation |
| Run Antivirus Scan | Antivirus Scan auf einem Gerät auslösen |
| Collect Investigation Package | Untersuchungspaket mit Artefakten vom Gerät sammeln |
| Restrict App Execution | Ausführung nicht vertrauenswürdiger Anwendungen einschränken |
| Release from Isolation | Geräteisolation wieder aufheben |
| Action Center | Übersicht über ausgeführte, ausstehende oder automatisierte Aktionen |
| False Positive | Erkennung war nicht bösartig |
| False Negative | Bedrohung wurde nicht erkannt |
| True Positive | Erkennung war tatsächlich bösartig oder sicherheitsrelevant |
| MSSP | Managed Security Service Provider |
| SOC | Security Operations Center |
| Escalation | Übergabe an zuständige interne oder externe Stelle |
| Business Impact | Auswirkung einer Maßnahme auf Benutzer, Fachprozess oder Betrieb |
| Ticket Documentation | Nachvollziehbare Dokumentation von Bewertung, Entscheidung und Maßnahme |