# Knowledge Transfer Session 3
## Operativer Security-Betrieb mit Microsoft Defender XDR

## Ziel der Session

Die Teilnehmer sollen lernen, wie ein Sicherheitsfall nach der Migration von McAfee/Trellix zu Microsoft Defender for Endpoint im täglichen Betrieb strukturiert bearbeitet wird.

Der Schwerpunkt liegt nicht mehr nur auf der Frage, ob ein Gerät technisch onboarded und geschützt ist. In Session 3 geht es darum, wie die interne IT einen Incident priorisiert, untersucht, mit Advanced Hunting vertieft, geeignete Response Actions auswählt und die Zusammenarbeit mit einem MSSP sowie dem späteren Microsoft Sentinel organisiert.

Der operative Grundablauf lautet:

```text
Incident erkennen
-> priorisieren
-> zuweisen
-> Alerts und Evidence untersuchen
-> Scope mit KQL erweitern
-> AIR-Ergebnisse prüfen
-> Response Action auswählen
-> dokumentieren und eskalieren
-> Incident kontrolliert abschließen
```

Diese Session ersetzt keine vollständige SOC- oder Forensik-Ausbildung. Die interne IT soll jedoch in der Lage sein, den Gerätekontext, Benutzerkontext und Business Impact zu liefern, Standardmaßnahmen zu verstehen und Entscheidungen des MSSP nachvollziehen zu können.

---

## Lernziele

Nach dieser Session können die Teilnehmer:

- neue Incidents in der Incident Queue priorisieren,
- Severity, Status, Assignment, Classification und Determination unterscheiden,
- einen Incident anhand von Alerts, Evidence, Entities und Attack Story untersuchen,
- die Device Page und Device Timeline in die Incident-Bewertung einbeziehen,
- einfache KQL-Abfragen erstellen und bestehende Queries anpassen,
- ähnliche Aktivitäten auf weiteren Geräten suchen,
- Ergebnisse einer Automated Investigation nachvollziehen,
- Pending und Completed Actions im Action Center prüfen,
- zwischen AV Scan, Investigation Package, Isolation, App Restriction und Live Response unterscheiden,
- den Business Impact einer Response Action bewerten,
- eine Custom Detection Rule fachlich und technisch entwerfen,
- Aufgaben zwischen interner IT, MSSP und später Microsoft Sentinel abgrenzen,
- einen Incident nachvollziehbar dokumentieren und schließen.

---

## 1. Vom Alert zum Incident

### Alert

Ein Alert ist eine einzelne sicherheitsrelevante Erkennung. Er kann beispielsweise durch Endpoint-Telemetrie, Defender Antivirus, Defender for Office 365, Defender for Identity oder eine Custom Detection Rule entstehen.

Ein Alert beantwortet zunächst:

```text
Welche verdächtige Aktivität wurde erkannt?
```

### Incident

Ein Incident ist der übergeordnete Sicherheitsfall. Microsoft Defender XDR korreliert zusammengehörige Alerts, Evidence und Assets zu einer gemeinsamen Angriffsgeschichte.

Ein Incident beantwortet:

```text
Welche zusammenhängende Angriffsgeschichte ergibt sich aus allen Signalen?
```

| Ebene | Beispiel |
|---|---|
| Alert 1 | Office-Anwendung startet PowerShell |
| Alert 2 | PowerShell lädt eine Datei herunter |
| Alert 3 | Datei verbindet sich zu externer IP-Adresse |
| Incident | Mögliche Kompromittierung eines Windows-11-Clients durch schädliches Office-Dokument |

### Warum nicht nur den einzelnen Alert bearbeiten?

Ein einzelner Alert kann nur einen Ausschnitt zeigen. Erst der Incident-Kontext zeigt:

- weitere Alerts,
- mehrere betroffene Geräte,
- beteiligte Benutzer,
- Dateien und Hashes,
- Netzwerkziele,
- zeitliche Zusammenhänge,
- bereits erfolgte automatische Maßnahmen.

**Merksatz:** Ein Alert ist ein Signal. Ein Incident ist der zusammenhängende Sicherheitsfall.

---

## 2. Incident Lifecycle

Ein konsistenter Incident Lifecycle verhindert, dass Incidents unbearbeitet bleiben oder ohne belastbare Bewertung geschlossen werden.

| Phase | Typische Tätigkeit | Ergebnis |
|---|---|---|
| New | Incident erscheint in der Queue | Noch nicht bewertet |
| Triage | Severity, Assets, Scope und Dringlichkeit prüfen | Priorität und Zuständigkeit stehen fest |
| In progress | Incident wird aktiv untersucht | Evidence und Business-Kontext werden gesammelt |
| Containment | Ausbreitung oder weitere Aktivität wird begrenzt | Risiko kurzfristig reduziert |
| Remediation | Schädliche Artefakte und Ursachen werden entfernt | Gerät oder Benutzer ist bereinigt |
| Recovery | Gerät und Fachprozess werden kontrolliert normalisiert | Betrieb wiederhergestellt |
| Resolved | Classification, Determination und Dokumentation vollständig | Incident nachvollziehbar abgeschlossen |

### Wichtige Felder

| Feld | Zweck |
|---|---|
| Severity | Technische Kritikalität und potenzieller Schaden |
| Priority | Reihenfolge der Bearbeitung unter Einbeziehung von Kontext |
| Status | New, In progress oder Resolved |
| Assigned to | Verantwortliche Person oder Team |
| Classification | True Positive, False Positive oder Informational/Expected Activity je nach Portaloptionen |
| Determination | Genauere Ursache, beispielsweise Malware, Phishing, Benign Positive oder Test Activity |
| Tags | Zusätzlicher Kontext, z. B. Pilot, VIP, kritischer Fachbereich oder MSSP |
| Comments | Nachvollziehbare Entscheidungen und Maßnahmen |

### Severity ist nicht gleich Business Priority

Ein Medium Alert auf einem Leitstellen-, Admin- oder Management-Gerät kann dringender sein als ein High Alert auf einem bereits isolierten Testgerät.

Priorisierung sollte mindestens berücksichtigen:

- aktive oder abgeschlossene Angriffshandlung,
- Hinweise auf Credential Theft,
- mögliche laterale Bewegung,
- Anzahl betroffener Geräte und Benutzer,
- Sensitivität des Geräts,
- Benutzerrolle,
- Datenabfluss oder externe Kommunikation,
- bereits erfolgte Blockierung oder Isolation,
- Betriebs- und Sicherheitsauswirkung.

---

## 3. Incident Investigation

Eine strukturierte Untersuchung beginnt mit der Incident-Übersicht und bewegt sich anschließend in die Details.

### Empfohlene Reihenfolge

| Schritt | Leitfrage |
|---:|---|
| 1 | Was ist die Zusammenfassung des Incidents? |
| 2 | Welche Alerts gehören zum Incident? |
| 3 | Welche Geräte, Benutzer und Mailboxen sind betroffen? |
| 4 | Welche Evidence wurde als malicious, suspicious oder clean bewertet? |
| 5 | Was zeigt die Attack Story beziehungsweise Alert Story? |
| 6 | Was geschah vor und nach dem Alert? |
| 7 | Gibt es dieselbe Aktivität auf weiteren Geräten? |
| 8 | Hat AIR bereits Maßnahmen ausgeführt oder vorgeschlagen? |
| 9 | Besteht noch aktive Gefahr? |
| 10 | Welche technische und organisatorische Reaktion ist angemessen? |

### Evidence und Entities

| Begriff | Bedeutung | Beispiele |
|---|---|---|
| Evidence | Konkretes Untersuchungsobjekt | Datei, Prozess, Registry Key, E-Mail, URL |
| Entity | Sicherheitsrelevantes Objekt im Zusammenhang | Benutzer, Gerät, IP-Adresse, Mailbox |
| Affected Asset | Betroffenes schützenswertes System oder Konto | Client, Server, Benutzerkonto |
| Verdict | Bewertung einer Evidence | Malicious, Suspicious, No threats found |

Eine Microsoft-Signatur oder ein normaler Dateiname beweist nicht, dass eine Aktivität legitim ist. Entscheidend bleibt der Kontext aus Pfad, Parent-Prozess, Command Line, Benutzer, Zeitpunkt und Folgeaktivität.

---

## 4. Device Investigation und Timeline

Die Device Page liefert den Endpunktkontext zu einem Incident.

Wichtige Bereiche:

- Overview,
- Alerts,
- Timeline,
- Security recommendations,
- Software inventory,
- Logged-on users,
- Response actions,
- Action Center beziehungsweise Action History.

### Typische Timeline-Fragen

- Welcher Prozess war der Ursprung?
- Welcher Child-Prozess wurde gestartet?
- Welche Command Line wurde verwendet?
- Wurde eine Datei erstellt oder ausgeführt?
- Gab es Netzwerkverbindungen?
- Wurde ein Benutzerkonto verwendet?
- Gibt es zeitlich angrenzende Alerts?
- Hat Defender bereits blockiert oder remediated?

### Beispiel

```text
WINWORD.EXE
-> powershell.exe -EncodedCommand ...
-> Datei in C:\Users\<User>\AppData\Local\Temp
-> Verbindung zu externer IP-Adresse
```

Diese Prozesskette ist deutlich relevanter als der Dateiname `powershell.exe` allein.

---

## 5. Advanced Hunting und KQL

Advanced Hunting beantwortet Fragen, die eine einzelne Portalansicht nicht vollständig beantworten kann.

Typische Betriebsfragen:

- Auf welchen Geräten wurde derselbe Hash gesehen?
- Welche Benutzer starteten denselben Prozess?
- Trat die Aktivität nur einmal oder tenantweit auf?
- Welche Geräte zeigen ähnliche Command Lines?
- Gibt es weitere Netzwerkverbindungen zur gleichen IP-Adresse?
- Welche Alerts wurden von einer bestimmten Detection Source erzeugt?

### Grundaufbau einer Query

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp desc
```

### Häufige Operatoren

| Operator | Zweck |
|---|---|
| `where` | Zeilen filtern |
| `project` | Spalten auswählen |
| `extend` | Berechnete Spalte ergänzen |
| `summarize` | Ergebnisse aggregieren |
| `count()` | Datensätze zählen |
| `dcount()` | Unterschiedliche Werte zählen |
| `distinct` | Eindeutige Kombinationen ausgeben |
| `top` | Häufigste oder höchste Ergebnisse anzeigen |
| `order by` | Ergebnisse sortieren |
| `join` | Tabellen anhand eines gemeinsamen Felds verbinden |
| `let` | Variable oder Teilquery definieren |
| `ago(7d)` | Relativer Zeitraum |

### Wichtige Tabellen

| Tabelle | Typische Nutzung |
|---|---|
| `AlertInfo` | Alerttitel, Severity, Quelle und Detection Source |
| `AlertEvidence` | Dateien, Benutzer, Geräte, E-Mails, URLs und IPs zu Alerts |
| `DeviceProcessEvents` | Prozessstarts und Prozessketten |
| `DeviceNetworkEvents` | Netzwerkverbindungen |
| `DeviceFileEvents` | Dateioperationen |
| `DeviceEvents` | Sonstige Endpoint-Ereignisse, unter anderem Security-Control-Ereignisse |
| `DeviceInfo` | Geräteinformationen und aktueller Gerätekontext |

### Best Practices

- Zeitraum früh eingrenzen.
- Erst relevante Zeilen filtern, dann `join` oder `summarize` verwenden.
- Nur benötigte Spalten projizieren.
- Ergebnisse immer im Business-Kontext bewerten.
- Queries versionieren und beschreiben.
- Eine Query nicht automatisch zu einer Detection Rule machen, bevor False Positives geprüft wurden.

---

## 6. Automated Investigation & Response

AIR untersucht unterstützte Alerts und verdächtige Entities automatisiert. Dabei werden Evidence-Verdicts erzeugt und abhängig vom Automation Level Remediation Actions automatisch durchgeführt oder zur Freigabe vorgelegt.

### Typische AIR-Ergebnisse

| Ergebnis | Bedeutung |
|---|---|
| Malicious | Evidence wurde als bösartig bewertet |
| Suspicious | Evidence ist verdächtig, aber nicht eindeutig bösartig |
| No threats found | Automatisierte Untersuchung fand keine bestätigte Bedrohung |
| Pending approval | Maßnahme wartet auf manuelle Freigabe |
| Remediated | Maßnahme wurde ausgeführt |
| Partially remediated | Nur ein Teil der gefundenen Probleme wurde behoben |

### Mögliche Remediation Actions

- Datei in Quarantäne verschieben,
- Prozess beenden,
- Registry Key entfernen,
- Dienst stoppen,
- Scheduled Task entfernen,
- Treiber deaktivieren.

### Automation Levels

Das Automation Level wird im MDE-Kontext über Device Groups gesteuert. Je nach Einstellung werden Maßnahmen automatisch durchgeführt oder müssen genehmigt werden.

**Wichtig:** AIR reduziert manuellen Aufwand, ersetzt aber nicht die abschließende Incident-Bewertung. Die IT muss prüfen, was untersucht, bewertet und verändert wurde.

---

## 7. Action Center

Das Action Center ist die zentrale Nachweisstelle für automatisierte und manuelle Aktionen.

Dort werden unter anderem angezeigt:

- Pending Actions,
- Completed Actions beziehungsweise History,
- Quelle der Aktion,
- ausführender Benutzer oder Automation,
- Zeitpunkt,
- Zielgerät oder Datei,
- Status und Fehler,
- Möglichkeit zur Freigabe, Ablehnung oder teilweise zum Undo.

### Betriebsfragen

- Welche Maßnahmen warten auf Freigabe?
- Welche Maßnahmen wurden automatisch ausgeführt?
- War die Aktion erfolgreich?
- Wurde sie auf dem richtigen Gerät ausgeführt?
- Muss eine legitime Datei wiederhergestellt werden?
- Ist das Gerät nach der Remediation weiterhin gefährdet?

---

## 8. Response Actions

Response Actions haben unterschiedliche Eingriffstiefen.

| Aktion | Zweck | Betriebswirkung |
|---|---|---|
| Run antivirus scan | Nach bekannter Malware oder Dateien suchen | Gering bis mittel |
| Collect investigation package | Forensische und Systemartefakte sammeln | Gering bis mittel |
| Initiate automated investigation | Automatisierte Analyse eines Geräts starten | Gering bis mittel |
| Restrict app execution | Ausführung auf vertrauenswürdige/Microsoft-signierte Anwendungen begrenzen | Hoch |
| Isolate device | Netzwerkkommunikation stark einschränken | Hoch |
| Live Response | Direkte Remote-Untersuchung und mögliche Remediation | Hoch, abhängig von Befehlen |
| Stop and quarantine file | Schädliche Datei stoppen und isolieren | Mittel bis hoch |

### Wann reicht ein AV Scan?

Ein AV Scan ist eine geeignete erste Maßnahme, wenn eine verdächtige Datei geprüft werden soll und keine Hinweise auf aktive Kompromittierung, Credential Theft, laterale Bewegung oder laufende Command-and-Control-Kommunikation vorliegen.

Ein Scan reicht nicht aus, wenn:

- der Angriff aktiv ist,
- mehrere verdächtige Prozessketten sichtbar sind,
- Zugangsdaten betroffen sein könnten,
- weitere Geräte betroffen sind,
- Persistenz oder Datenabfluss vermutet wird.

---

## 9. Device Isolation

Die Isolation trennt ein Gerät weitgehend vom Netzwerk, während erforderliche Defender-Kommunikation grundsätzlich erhalten bleiben soll.

### Zweck

- aktive Angreiferkommunikation unterbrechen,
- Datenabfluss reduzieren,
- laterale Bewegung erschweren,
- Zeit für Untersuchung und Remediation gewinnen.

### Vor der Isolation prüfen

| Prüffrage | Bedeutung |
|---|---|
| Ist die Aktivität noch aktiv? | Bei aktiver Gefahr schneller handeln |
| Besteht Ausbreitungsrisiko? | Isolation wird dringlicher |
| Ist das Gerät geschäftskritisch? | Business Owner informieren |
| Nutzt das Gerät Full-Tunnel-VPN oder besondere Proxys? | Erreichbarkeit nach Isolation beachten |
| Wer darf die Maßnahme freigeben? | Governance einhalten |
| Gibt es einen alternativen Zugriff oder Ersatzclient? | Betriebsunterbrechung reduzieren |

### Nach der Isolation

- Status im Action Center prüfen,
- Benutzer und Service Desk informieren,
- Incident und Ticket aktualisieren,
- Untersuchung fortsetzen,
- Zugangsdaten bei Bedarf zurücksetzen,
- Bereinigung validieren,
- Freigabe zur Aufhebung dokumentieren.

---

## 10. Live Response

Live Response stellt eine abgesicherte Remote-Shell auf einem onboarded Gerät bereit. Sie ist für tiefere Untersuchungen und gezielte Reaktionen gedacht.

Mögliche Aufgaben:

- Prozesse und Netzwerkverbindungen anzeigen,
- Dateien analysieren,
- Artefakte herunterladen,
- freigegebene Skripte aus der Library ausführen,
- Remediation Actions durchführen oder rückgängig machen.

### Risiken

- direkte Änderungen auf einem möglicherweise kompromittierten System,
- mögliche Veränderung forensischer Artefakte,
- Business Impact durch Stoppen von Prozessen oder Löschen von Dateien,
- Missbrauch bei zu weit gefassten Rollen,
- Übertragung sensibler Dateien.

### Governance

- separate Rollen für Basic und Advanced Live Response,
- nur freigegebene Test- oder Incident-Geräte,
- Ticketreferenz und Zweck dokumentieren,
- Command Log sichern,
- keine unbekannten Skripte oder Binaries hochladen,
- Vier-Augen-Prinzip für eingreifende Maßnahmen erwägen.

---

## 11. Custom Detection Rules

Eine Custom Detection Rule führt eine Advanced-Hunting-Query regelmäßig aus und erzeugt bei Treffern Alerts.

Geeignete Anwendungsfälle:

- wiederkehrendes ungewöhnliches Admin-Tool auf normalen Clients,
- spezifische interne Angriffsmuster,
- bekannte unerwünschte Command Lines,
- Policy- oder Konfigurationsabweichungen,
- kundenspezifische Indicators und Prozesse.

### Voraussetzungen einer guten Detection

| Kriterium | Leitfrage |
|---|---|
| Eindeutiger Use Case | Welches Risiko soll erkannt werden? |
| Stabile Query | Liefert sie reproduzierbare Ergebnisse? |
| Niedrige False-Positive-Rate | Wurden legitime Anwendungen geprüft? |
| Relevante Entity | Wird Device, Account oder Mailbox korrekt zugeordnet? |
| Verständlicher Titel | Erkennt ein Operator sofort das Problem? |
| Passende Severity | Entspricht sie Risiko und Scope? |
| Runbook | Wer untersucht und reagiert bei einem Treffer? |
| Review | Wird die Regel regelmäßig überprüft? |

Eine Custom Detection darf nicht nur technisch funktionieren. Sie muss auch einen definierten Bearbeitungsprozess besitzen.

---

## 12. Microsoft Sentinel und Defender XDR

### Defender XDR

Defender XDR korreliert Signale aus Microsoft-Sicherheitsprodukten und bietet tiefe Untersuchungs- und Response-Funktionen für Endpoints, Identitäten, E-Mail und Cloud Apps.

### Microsoft Sentinel

Microsoft Sentinel ist ein SIEM- und SOAR-System. Es kann zusätzliche Datenquellen aufnehmen, beispielsweise:

- Azure Activity Logs,
- Firewall- und Proxy-Logs,
- Windows- und Linux-Logs,
- Netzwerkgeräte,
- SaaS- und Drittanbieterprodukte,
- kundenspezifische Anwendungen.

### Zusammenspiel

| Defender XDR | Microsoft Sentinel |
|---|---|
| Tiefer Microsoft-Security- und Endpoint-Kontext | Breite Datenquellen über Microsoft hinaus |
| Device Timeline und Response Actions | SIEM-Korrelation, Analytics und Automation |
| AIR und Action Center | Playbooks und SOAR-Prozesse |
| Advanced Hunting über Defender-Daten | KQL über Sentinel- und Defender-Daten im einheitlichen Portal |

Für den Kunden bedeutet dies: Die interne IT sollte Defender XDR bereits sicher bedienen können, bevor Sentinel zusätzliche Logquellen und übergreifende Use Cases einführt.

---

## 13. Zusammenarbeit mit einem MSSP

Ein MSSP kann Monitoring, Triage und tiefe Analyse übernehmen. Die interne IT bleibt jedoch für lokalen Kontext und betriebliche Entscheidungen unverzichtbar.

| Aufgabe | MSSP/SOC | Interne IT |
|---|---|---|
| 24/7 Monitoring | häufig verantwortlich | informiert |
| Erste technische Triage | verantwortlich | unterstützt |
| Device- und User-Kontext | fragt an | liefert |
| Business-Kritikalität | berücksichtigt | entscheidet |
| Isolationsempfehlung | spricht aus | genehmigt nach Prozess oder delegiert |
| Live Response | je nach Vertrag | kontrolliert und freigegeben |
| Benutzerkommunikation | selten | verantwortlich |
| Geräteersatz und Rebuild | unterstützt | verantwortlich |
| Incident-Dokumentation | Security-Sicht | Betriebs- und Ticket-Sicht |
| Lessons Learned | gemeinsam | gemeinsam |

### Mindestinformationen bei einer Eskalation

- Incident- und Ticketnummer,
- Zeitpunkt und Severity,
- betroffene Geräte und Benutzer,
- Business-Kritikalität,
- beobachtete Prozesskette,
- relevante Hashes, IPs und URLs,
- bereits durchgeführte Aktionen,
- aktueller Isolation- und Gerätestatus,
- offene Freigaben,
- gewünschte nächste Entscheidung.

---

## 14. Incident-Abschluss

Ein Incident sollte erst geschlossen werden, wenn mindestens folgende Fragen beantwortet sind:

- Was ist passiert?
- Welche Assets waren betroffen?
- War der Incident ein True Positive oder False Positive?
- Wurde die Ursache beseitigt?
- Wurden alle Maßnahmen erfolgreich abgeschlossen?
- Besteht noch Restrisiko?
- Muss ein Benutzerkennwort oder Token zurückgesetzt werden?
- Wurde eine Ausnahme oder Policy-Änderung notwendig?
- Sind Ticket, Kommentare und Evidence vollständig?
- Gibt es Lessons Learned oder Folgeaufgaben?

### Abschlussvorlage

| Feld | Eintrag |
|---|---|
| Classification |  |
| Determination |  |
| Root Cause |  |
| Betroffene Assets |  |
| Durchgeführte Maßnahmen |  |
| Validierung |  |
| Restrisiko |  |
| Ticketnummer |  |
| Folgeaufgaben |  |
| Freigabe zum Abschluss |  |

---

## Zusammenfassung

| Thema | Kernaussage |
|---|---|
| Incident | Übergeordneter Sicherheitsfall aus korrelierten Alerts und Evidence |
| Triage | Technisches Risiko und Business-Kontext gemeinsam bewerten |
| Investigation | Incident Story, Alerts, Evidence, Entities und Timeline zusammenführen |
| Advanced Hunting | Scope und ähnliche Aktivitäten tenantweit prüfen |
| AIR | Automatisierte Untersuchung und Remediation nachvollziehen, nicht blind vertrauen |
| Action Center | Zentrale Nachweisstelle für Pending und Completed Actions |
| Response Actions | Eingriffstiefe und Business Impact berücksichtigen |
| Isolation | Aktive Gefahr eindämmen, aber kontrolliert freigeben und aufheben |
| Live Response | Leistungsfähige Remote-Untersuchung mit strenger Governance |
| Custom Detection | Wiederkehrende kundenspezifische Erkennung mit Runbook und Review |
| Sentinel | Ergänzt Defender XDR um SIEM-, SOAR- und Drittanbieter-Daten |
| MSSP | Übernimmt Monitoring und Analyse, interne IT liefert Kontext und Betriebsentscheidungen |
| Incident Closure | Erst nach vollständiger Bewertung, Remediation und Dokumentation |

---

## Vokabelliste

| Begriff | Kurzbeschreibung |
|---|---|
| Incident | Zusammenhängender Sicherheitsfall aus Alerts, Evidence und Assets |
| Alert | Einzelne sicherheitsrelevante Erkennung |
| Correlation | Automatisches Zusammenführen zusammengehöriger Signale |
| Incident Queue | Zentrale Liste der Incidents |
| Triage | Erste Priorisierung und Zuständigkeitsklärung |
| Severity | Technische Kritikalität |
| Priority | Tatsächliche Bearbeitungsreihenfolge unter Einbeziehung von Kontext |
| Status | Bearbeitungsstand eines Incidents |
| Assignment | Zuweisung an Bearbeiter oder Team |
| Classification | Grundsätzliche Bewertung, z. B. True Positive oder False Positive |
| Determination | Genauere Ursache oder Art der Aktivität |
| Attack Story | Grafische und zeitliche Darstellung des Angriffsverlaufs |
| Alert Story | Detaildarstellung eines Alerts |
| Evidence | Datei, Prozess, E-Mail, URL oder anderes Untersuchungsobjekt |
| Entity | Benutzer, Gerät, IP oder anderes sicherheitsrelevantes Objekt |
| Affected Asset | Betroffenes Gerät, Konto oder System |
| Verdict | Bewertung einer Evidence |
| Device Page | Zentrale Defender-Ansicht eines Endpoints |
| Device Timeline | Zeitliche Endpoint-Telemetrie |
| Parent Process | Prozess, der einen anderen Prozess gestartet hat |
| Child Process | Von einem Parent Process gestarteter Prozess |
| Command Line | Aufrufparameter eines Prozesses |
| Advanced Hunting | Proaktive Abfrage von Defender- und Sentinel-Daten |
| KQL | Kusto Query Language |
| Schema | Tabellen- und Spaltenstruktur für Hunting Queries |
| AlertInfo | Hunting-Tabelle für Alert-Metadaten |
| AlertEvidence | Hunting-Tabelle für Alert-Evidence |
| DeviceProcessEvents | Hunting-Tabelle für Prozessstarts |
| DeviceNetworkEvents | Hunting-Tabelle für Netzwerkverbindungen |
| DeviceFileEvents | Hunting-Tabelle für Dateiaktivitäten |
| AIR | Automated Investigation and Response |
| Automated Investigation | Automatisierte Untersuchung eines Alerts oder Geräts |
| Remediation | Beseitigung einer Bedrohung oder eines Artefakts |
| Pending Action | Maßnahme wartet auf Freigabe |
| Action Center | Zentrale Ansicht manueller und automatisierter Aktionen |
| Investigation Package | Sammlung technischer Artefakte eines Geräts |
| Antivirus Scan | Lokale Malware-Prüfung eines Geräts |
| Device Isolation | Weitgehende Netzwerkisolation eines Geräts |
| Restrict App Execution | Einschränkung ausführbarer Anwendungen |
| Live Response | Remote-Shell für Untersuchung und Reaktion |
| Custom Detection | Eigene regelmäßige Erkennung auf Basis einer Hunting Query |
| Detection Frequency | Ausführungsintervall einer Detection Rule |
| False Positive | Legitime Aktivität wurde fälschlich als verdächtig erkannt |
| True Positive | Tatsächlich sicherheitsrelevante oder bösartige Aktivität |
| MSSP | Managed Security Service Provider |
| SOC | Security Operations Center |
| SIEM | Security Information and Event Management |
| SOAR | Security Orchestration, Automation and Response |
| Microsoft Sentinel | Microsoft SIEM- und SOAR-Plattform |
| Escalation | Übergabe an eine zuständige oder höher priorisierte Stelle |
| Business Impact | Betriebliche Auswirkung eines Incidents oder einer Maßnahme |
| Runbook | Standardisierter Handlungsablauf |
| Chain of Custody | Nachvollziehbarer Umgang mit forensischen Beweismitteln |
| Lessons Learned | Nachbereitung und Verbesserung nach einem Incident |

---

## Microsoft-Referenzen

- https://learn.microsoft.com/defender-xdr/incidents-overview
- https://learn.microsoft.com/defender-xdr/manage-incidents
- https://learn.microsoft.com/defender-xdr/investigate-incidents
- https://learn.microsoft.com/defender-xdr/advanced-hunting-overview
- https://learn.microsoft.com/defender-xdr/advanced-hunting-query-language
- https://learn.microsoft.com/defender-endpoint/automated-investigations
- https://learn.microsoft.com/defender-endpoint/manage-auto-investigation
- https://learn.microsoft.com/defender-endpoint/respond-machine-alerts
- https://learn.microsoft.com/defender-endpoint/live-response
- https://learn.microsoft.com/defender-xdr/custom-detection-rules
- https://learn.microsoft.com/azure/sentinel/microsoft-sentinel-defender-portal
