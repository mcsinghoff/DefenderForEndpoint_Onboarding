# Knowledge Transfer Session 3
## Operativer Security-Betrieb mit Microsoft Defender XDR

## Hinweis zu den Portalbezeichnungen

Die Unterlagen nennen englische Bezeichnungen der Microsoft-Portale im Format `English label (deutsche Bezeichnung)`, zum Beispiel `Advanced hunting (Erweiterte Suche)`. Dadurch können die Übungen unabhängig davon verwendet werden, ob Screenshots, Microsoft-Dokumentation oder die deutsche Portaloberfläche genutzt werden. Microsoft kann Menübezeichnungen durch Portalupdates geringfügig ändern.

---

## Ziel der Session

Die Teilnehmer sollen lernen, wie ein Sicherheitsfall nach der Migration von McAfee/Trellix zu Microsoft Defender for Endpoint im täglichen Betrieb strukturiert bearbeitet wird.

Der Schwerpunkt liegt nicht mehr nur auf der Frage, ob ein Gerät technisch onboarded und geschützt ist. In Session 3 geht es darum, wie die interne IT einen Incident priorisiert, untersucht, mit Advanced Hunting (Erweiterte Suche) vertieft, geeignete Response Actions (Antwortaktionen) auswählt und die Zusammenarbeit mit einem MSSP sowie dem späteren Microsoft Sentinel organisiert.

Der operative Grundablauf lautet:

```text
Incident erkennen
-> priorisieren
-> zuweisen
-> Alerts (Warnungen) und Evidence (Beweise) untersuchen
-> Scope mit KQL erweitern
-> AIR-Ergebnisse prüfen
-> Response Action (Antwortaktion) auswählen
-> dokumentieren und eskalieren
-> Incident kontrolliert abschließen
```

Diese Session ersetzt keine vollständige SOC- oder Forensik-Ausbildung. Die interne IT soll jedoch in der Lage sein, den Gerätekontext, Benutzerkontext und Business Impact (betriebliche Auswirkung) zu liefern, Standardmaßnahmen zu verstehen und Entscheidungen des MSSP nachvollziehen zu können.

---

## Lernziele

Nach dieser Session können die Teilnehmer:

- neue Incidents in der Incident Queue (Incidentwarteschlange) priorisieren,
- Severity (Schweregrad), Status, Assignment (Zuweisung), Classification (Klassifizierung) und Determination (Bestimmung) unterscheiden,
- einen Incident anhand von Alerts (Warnungen), Evidence (Beweise), Entities (Entitäten) und Attack Story (Angriffsgeschichte) untersuchen,
- die Device Page (Geräteseite) und Device Timeline (Gerätezeitachse) in die Incident-Bewertung einbeziehen,
- einfache KQL-Abfragen erstellen und bestehende Queries anpassen,
- ähnliche Aktivitäten auf weiteren Geräten suchen,
- Ergebnisse einer Automated Investigation (Automatisierte Untersuchung) nachvollziehen,
- Pending (Ausstehend) und Completed Actions (abgeschlossene Aktionen) im Action Center (Aktionscenter) prüfen,
- zwischen AV Scan (Antivirusscan), Investigation Package (Untersuchungspaket), Isolation, App Restriction (App-Einschränkung) und Live Response (Liveantwort) unterscheiden,
- den Business Impact (betriebliche Auswirkung) einer Response Action (Antwortaktion) bewerten,
- eine Custom Detection Rule (benutzerdefinierte Erkennungsregel) fachlich und technisch entwerfen,
- Aufgaben zwischen interner IT, MSSP und später Microsoft Sentinel abgrenzen,
- einen Incident nachvollziehbar dokumentieren und schließen.

---

## 1. Vom Alert (Warnung) zum Incident

### Alert (Warnung)

Ein Alert (Warnung) ist eine einzelne sicherheitsrelevante Erkennung. Er kann beispielsweise durch Endpoint-Telemetrie, Defender Antivirus, Defender for Office 365, Defender for Identity oder eine Custom Detection Rule (benutzerdefinierte Erkennungsregel) entstehen.

Ein Alert (Warnung) beantwortet zunächst:

```text
Welche verdächtige Aktivität wurde erkannt?
```

### Incident

Ein Incident ist der übergeordnete Sicherheitsfall. Microsoft Defender XDR korreliert zusammengehörige Alerts (Warnungen), Evidence (Beweise) und Assets (Bestand) zu einer gemeinsamen Angriffsgeschichte.

Ein Incident beantwortet:

```text
Welche zusammenhängende Angriffsgeschichte ergibt sich aus allen Signalen?
```

| Ebene | Beispiel |
|---|---|
| Alert (Warnung) 1 | Office-Anwendung startet PowerShell |
| Alert (Warnung) 2 | PowerShell lädt eine Datei herunter |
| Alert (Warnung) 3 | Datei verbindet sich zu externer IP-Adresse |
| Incident | Mögliche Kompromittierung eines Windows-11-Clients durch schädliches Office-Dokument |

### Warum nicht nur den einzelnen Alert (Warnung) bearbeiten?

Ein einzelner Alert (Warnung) kann nur einen Ausschnitt zeigen. Erst der Incident-Kontext zeigt:

- weitere Alerts (Warnungen),
- mehrere betroffene Geräte,
- beteiligte Benutzer,
- Dateien und Hashes,
- Netzwerkziele,
- zeitliche Zusammenhänge,
- bereits erfolgte automatische Maßnahmen.

**Merksatz:** Ein Alert (Warnung) ist ein Signal. Ein Incident ist der zusammenhängende Sicherheitsfall.

---

## 2. Incident Lifecycle

Ein konsistenter Incident Lifecycle verhindert, dass Incidents unbearbeitet bleiben oder ohne belastbare Bewertung geschlossen werden.

| Phase | Typische Tätigkeit | Ergebnis |
|---|---|---|
| New (Neu) | Incident erscheint in der Queue | Noch nicht bewertet |
| Triage | Severity (Schweregrad), Assets (Bestand), Scope und Dringlichkeit prüfen | Priorität und Zuständigkeit stehen fest |
| In progress (In Bearbeitung) | Incident wird aktiv untersucht | Evidence (Beweise) und Business-Kontext werden gesammelt |
| Containment | Ausbreitung oder weitere Aktivität wird begrenzt | Risiko kurzfristig reduziert |
| Remediation (Behebung) | Schädliche Artefakte und Ursachen werden entfernt | Gerät oder Benutzer ist bereinigt |
| Recovery | Gerät und Fachprozess werden kontrolliert normalisiert | Betrieb wiederhergestellt |
| Resolved (Gelöst) | Classification (Klassifizierung), Determination (Bestimmung) und Dokumentation vollständig | Incident nachvollziehbar abgeschlossen |

### Wichtige Felder

| Feld | Zweck |
|---|---|
| Severity (Schweregrad) | Technische Kritikalität und potenzieller Schaden |
| Priority (Priorität) | Reihenfolge der Bearbeitung unter Einbeziehung von Kontext |
| Status | New (Neu), In progress (In Bearbeitung) oder Resolved (Gelöst) |
| Assigned to (Zuweisen zu) | Verantwortliche Person oder Team |
| Classification (Klassifizierung) | True Positive (Richtig positiv), False Positive (Falsch positiv) oder Informational/Expected Activity (Informativ/Erwartete Aktivität) je nach Portaloptionen |
| Determination (Bestimmung) | Genauere Ursache, beispielsweise Malware, Phishing, Benign Positive (Legitim positiv) oder Test Activity (Testaktivität) |
| Tags (Incidenttags) | Zusätzlicher Kontext, z. B. Pilot, VIP, kritischer Fachbereich oder MSSP |
| Comments (Kommentare) | Nachvollziehbare Entscheidungen und Maßnahmen |

### Severity (Schweregrad) ist nicht gleich Business Priority (Priorität)

Ein Medium (Mittel) Alert (Warnung) auf einem Leitstellen-, Admin- oder Management-Gerät kann dringender sein als ein High (Hoch) Alert (Warnung) auf einem bereits isolierten Testgerät.

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

## 3. Incident Investigation (Untersuchung)

Eine strukturierte Untersuchung beginnt mit der Incident-Übersicht und bewegt sich anschließend in die Details.

### Empfohlene Reihenfolge

| Schritt | Leitfrage |
|---:|---|
| 1 | Was ist die Zusammenfassung des Incidents? |
| 2 | Welche Alerts (Warnungen) gehören zum Incident? |
| 3 | Welche Geräte, Benutzer und Mailboxen sind betroffen? |
| 4 | Welche Evidence (Beweise) wurde als malicious, suspicious oder clean bewertet? |
| 5 | Was zeigt die Attack Story (Angriffsgeschichte) beziehungsweise Alert Story (Warnungsverlauf)? |
| 6 | Was geschah vor und nach dem Alert (Warnung)? |
| 7 | Gibt es dieselbe Aktivität auf weiteren Geräten? |
| 8 | Hat AIR bereits Maßnahmen ausgeführt oder vorgeschlagen? |
| 9 | Besteht noch aktive Gefahr? |
| 10 | Welche technische und organisatorische Reaktion ist angemessen? |

### Evidence (Beweise) und Entities (Entitäten)

| Begriff | Bedeutung | Beispiele |
|---|---|---|
| Evidence (Beweise) | Konkretes Untersuchungsobjekt | Datei, Prozess, Registry Key, E-Mail, URL |
| Entity (Entität) | Sicherheitsrelevantes Objekt im Zusammenhang | Benutzer, Gerät, IP-Adresse, Mailbox |
| Affected Asset (betroffene Ressource) | Betroffenes schützenswertes System oder Konto | Client, Server, Benutzerkonto |
| Verdict (Bewertung) | Bewertung einer Evidence (Beweise) | Malicious (Bösartig), Suspicious (Verdächtig), No threats found (Keine Bedrohungen gefunden) |

Eine Microsoft-Signatur oder ein normaler Dateiname beweist nicht, dass eine Aktivität legitim ist. Entscheidend bleibt der Kontext aus Pfad, Parent-Prozess, Command Line (Befehlszeile), Benutzer, Zeitpunkt und Folgeaktivität.

---

## 4. Device (Gerät) Investigation (Untersuchung) und Timeline (Zeitachse)


### Typische Timeline (Zeitachse)-Fragen

- Welcher Prozess war der Ursprung?
- Welcher Child-Prozess wurde gestartet?
- Welche Command Line (Befehlszeile) wurde verwendet?
- Wurde eine Datei erstellt oder ausgeführt?
- Gab es Netzwerkverbindungen?
- Wurde ein Benutzerkonto verwendet?
- Gibt es zeitlich angrenzende Alerts (Warnungen)?
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

## 5. Advanced Hunting (Erweiterte Suche) und KQL

Advanced Hunting (Erweiterte Suche) beantwortet Fragen, die eine einzelne Portalansicht nicht vollständig beantworten kann.

Typische Betriebsfragen:

- Auf welchen Geräten wurde derselbe Hash gesehen?
- Welche Benutzer starteten denselben Prozess?
- Trat die Aktivität nur einmal oder tenantweit auf?
- Welche Geräte zeigen ähnliche Command Lines?
- Gibt es weitere Netzwerkverbindungen zur gleichen IP-Adresse?
- Welche Alerts (Warnungen) wurden von einer bestimmten Detection Source (Erkennungsquelle) erzeugt?

### Grundaufbau einer Query (Abfrage)

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
| `AlertInfo` | Alerttitel, Severity (Schweregrad), Quelle und Detection Source (Erkennungsquelle) |
| `AlertEvidence` | Dateien, Benutzer, Geräte, E-Mails, URLs und IPs zu Alerts (Warnungen) |
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
- Eine Query (Abfrage) nicht automatisch zu einer Detection Rule (Erkennungsregel) machen, bevor False Positives (Falsch-positive Ergebnisse) geprüft wurden.

---

## 6. Automated Investigation & Response (Automatisierte Untersuchung und Reaktion)

AIR untersucht unterstützte Alerts (Warnungen) und verdächtige Entities (Entitäten) automatisiert. Dabei werden Evidence (Beweise)-Verdicts (Bewertungen) erzeugt und abhängig vom Automation Level (Automatisierungsebene) Remediation Actions (Behebungsaktionen) automatisch durchgeführt oder zur Freigabe vorgelegt.

### Typische AIR-Ergebnisse

| Ergebnis | Bedeutung |
|---|---|
| Malicious (Bösartig) | Evidence (Beweise) wurde als bösartig bewertet |
| Suspicious (Verdächtig) | Evidence (Beweise) ist verdächtig, aber nicht eindeutig bösartig |
| No threats found (Keine Bedrohungen gefunden) | Automatisierte Untersuchung fand keine bestätigte Bedrohung |
| Pending approval (Genehmigung ausstehend) | Maßnahme wartet auf manuelle Freigabe |
| Remediated (Behoben) | Maßnahme wurde ausgeführt |
| Partially remediated (Teilweise behoben) | Nur ein Teil der gefundenen Probleme wurde behoben |

### Mögliche Remediation Actions (Behebungsaktionen)

- Datei in Quarantäne verschieben,
- Prozess beenden,
- Registry Key entfernen,
- Dienst stoppen,
- Scheduled Task entfernen,
- Treiber deaktivieren.

### Automation Levels (Automatisierungsebenen)

Das Automation Level (Automatisierungsebene) wird im MDE-Kontext über Device Groups (Gerätegruppen) gesteuert. Je nach Einstellung werden Maßnahmen automatisch durchgeführt oder müssen genehmigt werden.

**Wichtig:** AIR reduziert manuellen Aufwand, ersetzt aber nicht die abschließende Incident-Bewertung. Die IT muss prüfen, was untersucht, bewertet und verändert wurde.

---

## 7. Action Center (Aktionscenter)

Das Action Center (Aktionscenter) ist die zentrale Nachweisstelle für automatisierte und manuelle Aktionen.

Dort werden unter anderem angezeigt:

- Pending Actions (ausstehende Aktionen),
- Completed Actions (abgeschlossene Aktionen) beziehungsweise History (Verlauf),
- Quelle der Aktion,
- ausführender Benutzer oder Automation,
- Zeitpunkt,
- Zielgerät oder Datei,
- Status und Fehler,
- Möglichkeit zur Freigabe, Ablehnung oder teilweise zum Undo (Rückgängig machen).

### Betriebsfragen

- Welche Maßnahmen warten auf Freigabe?
- Welche Maßnahmen wurden automatisch ausgeführt?
- War die Aktion erfolgreich?
- Wurde sie auf dem richtigen Gerät ausgeführt?
- Muss eine legitime Datei wiederhergestellt werden?
- Ist das Gerät nach der Remediation (Behebung) weiterhin gefährdet?

---

## 8. Response Actions (Antwortaktionen)

Response Actions (Antwortaktionen) haben unterschiedliche Eingriffstiefen.

| Aktion | Zweck | Betriebswirkung |
|---|---|---|
| Run antivirus scan (Antivirusscan ausführen) | Nach bekannter Malware oder Dateien suchen | Gering bis mittel |
| Collect investigation package (Untersuchungspaket sammeln) | Forensische und Systemartefakte sammeln | Gering bis mittel |
| Initiate automated investigation (Automatisierte Untersuchung initiieren) | Automatisierte Analyse eines Geräts starten | Gering bis mittel |
| Restrict app execution (App-Ausführung einschränken) | Ausführung auf vertrauenswürdige/Microsoft-signierte Anwendungen begrenzen | Hoch |
| Isolate device (Gerät isolieren) | Netzwerkkommunikation stark einschränken | Hoch |
| Live Response (Liveantwort) | Direkte Remote-Untersuchung und mögliche Remediation (Behebung) | Hoch, abhängig von Befehlen |
| Stop and quarantine file (Datei beenden und unter Quarantäne stellen) | Schädliche Datei stoppen und isolieren | Mittel bis hoch |

### Wann reicht ein AV Scan (Antivirusscan)?

Ein AV Scan (Antivirusscan) ist eine geeignete erste Maßnahme, wenn eine verdächtige Datei geprüft werden soll und keine Hinweise auf aktive Kompromittierung, Credential Theft, laterale Bewegung oder laufende Command-and-Control-Kommunikation vorliegen.

Ein Scan reicht nicht aus, wenn:

- der Angriff aktiv ist,
- mehrere verdächtige Prozessketten sichtbar sind,
- Zugangsdaten betroffen sein könnten,
- weitere Geräte betroffen sind,
- Persistenz oder Datenabfluss vermutet wird.

---

## 9. Device Isolation (Geräteisolation)

Die Isolation trennt ein Gerät weitgehend vom Netzwerk, während erforderliche Defender-Kommunikation grundsätzlich erhalten bleiben soll.

### Zweck

- aktive Angreiferkommunikation unterbrechen,
- Datenabfluss reduzieren,
- laterale Bewegung erschweren,
- Zeit für Untersuchung und Remediation (Behebung) gewinnen.

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

- Status im Action Center (Aktionscenter) prüfen,
- Benutzer und Service Desk informieren,
- Incident und Ticket aktualisieren,
- Untersuchung fortsetzen,
- Zugangsdaten bei Bedarf zurücksetzen,
- Bereinigung validieren,
- Freigabe zur Aufhebung dokumentieren.

---

## 10. Live Response (Liveantwort)

Live Response (Liveantwort) stellt eine abgesicherte Remote-Shell auf einem onboarded Gerät bereit. Sie ist für tiefere Untersuchungen und gezielte Reaktionen gedacht.

Mögliche Aufgaben:

- Prozesse und Netzwerkverbindungen anzeigen,
- Dateien analysieren,
- Artefakte herunterladen,
- freigegebene Skripte aus der Library ausführen,
- Remediation Actions (Behebungsaktionen) durchführen oder rückgängig machen.

### Risiken

- direkte Änderungen auf einem möglicherweise kompromittierten System,
- mögliche Veränderung forensischer Artefakte,
- Business Impact (betriebliche Auswirkung) durch Stoppen von Prozessen oder Löschen von Dateien,
- Missbrauch bei zu weit gefassten Rollen,
- Übertragung sensibler Dateien.

---

## 11. Custom Detection Rules (benutzerdefinierte Erkennungsregeln)

Eine Custom Detection Rule (benutzerdefinierte Erkennungsregel) führt eine Advanced-Hunting (Bedrohungssuche)-Query (Abfrage) regelmäßig aus und erzeugt bei Treffern Alerts (Warnungen).

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
| Stabile Query (Abfrage) | Liefert sie reproduzierbare Ergebnisse? |
| Niedrige False-Positive-Rate | Wurden legitime Anwendungen geprüft? |
| Relevante Entity (Entität) | Wird Device (Gerät), Account (Konto) oder Mailbox korrekt zugeordnet? |
| Verständlicher Titel | Erkennt ein Operator sofort das Problem? |
| Passende Severity (Schweregrad) | Entspricht sie Risiko und Scope? |
| Runbook | Wer untersucht und reagiert bei einem Treffer? |
| Review | Wird die Regel regelmäßig überprüft? |

Eine Custom Detection (benutzerdefinierte Erkennung) darf nicht nur technisch funktionieren. Sie muss auch einen definierten Bearbeitungsprozess besitzen.

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
| Device Timeline (Gerätezeitachse) und Response Actions (Antwortaktionen) | SIEM-Korrelation, Analytics und Automation |
| AIR und Action Center (Aktionscenter) | Playbooks und SOAR-Prozesse |
| Advanced Hunting (Erweiterte Suche) über Defender-Daten | KQL über Sentinel- und Defender-Daten im einheitlichen Portal |

Für den Kunden bedeutet dies: Die interne IT sollte Defender XDR bereits sicher bedienen können, bevor Sentinel zusätzliche Logquellen und übergreifende Use Cases einführt.

---

## 13. Zusammenarbeit mit einem MSSP

Ein MSSP kann Monitoring, Triage und tiefe Analyse übernehmen. Die interne IT bleibt jedoch für lokalen Kontext und betriebliche Entscheidungen unverzichtbar.

| Aufgabe | MSSP/SOC | Interne IT |
|---|---|---|
| 24/7 Monitoring | häufig verantwortlich | informiert |
| Erste technische Triage | verantwortlich | unterstützt |
| Device (Gerät)- und User-Kontext | fragt an | liefert |
| Business-Kritikalität | berücksichtigt | entscheidet |
| Isolationsempfehlung | spricht aus | genehmigt nach Prozess oder delegiert |
| Live Response (Liveantwort) | je nach Vertrag | kontrolliert und freigegeben |
| Benutzerkommunikation | selten | verantwortlich |
| Geräteersatz und Rebuild | unterstützt | verantwortlich |
| Incident-Dokumentation | Security-Sicht | Betriebs- und Ticket-Sicht |
| Lessons Learned | gemeinsam | gemeinsam |

### Mindestinformationen bei einer Eskalation

- Incident- und Ticketnummer,
- Zeitpunkt und Severity (Schweregrad),
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
- Welche Assets (Bestand) waren betroffen?
- War der Incident ein True Positive (Richtig positiv) oder False Positive (Falsch positiv)?
- Wurde die Ursache beseitigt?
- Wurden alle Maßnahmen erfolgreich abgeschlossen?
- Besteht noch Restrisiko?
- Muss ein Benutzerkennwort oder Token zurückgesetzt werden?
- Wurde eine Ausnahme oder Policy-Änderung notwendig?
- Sind Ticket, Kommentare und Evidence (Beweise) vollständig?
- Gibt es Lessons Learned oder Folgeaufgaben?

### Abschlussvorlage

| Feld | Eintrag |
|---|---|
| Classification (Klassifizierung) |  |
| Determination (Bestimmung) |  |
| Root Cause (Grundursache) |  |
| Betroffene Assets (Bestand) |  |
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
| Incident | Übergeordneter Sicherheitsfall aus korrelierten Alerts (Warnungen) und Evidence (Beweise) |
| Triage | Technisches Risiko und Business-Kontext gemeinsam bewerten |
| Investigation (Untersuchung) | Incident Story (Incidentverlauf), Alerts (Warnungen), Evidence (Beweise), Entities (Entitäten) und Timeline (Zeitachse) zusammenführen |
| Advanced Hunting (Erweiterte Suche) | Scope und ähnliche Aktivitäten tenantweit prüfen |
| AIR | Automatisierte Untersuchung und Remediation (Behebung) nachvollziehen, nicht blind vertrauen |
| Action Center (Aktionscenter) | Zentrale Nachweisstelle für Pending (Ausstehend) und Completed Actions (abgeschlossene Aktionen) |
| Response Actions (Antwortaktionen) | Eingriffstiefe und Business Impact (betriebliche Auswirkung) berücksichtigen |
| Isolation | Aktive Gefahr eindämmen, aber kontrolliert freigeben und aufheben |
| Live Response (Liveantwort) | Leistungsfähige Remote-Untersuchung mit strenger Governance |
| Custom Detection (benutzerdefinierte Erkennung) | Wiederkehrende kundenspezifische Erkennung mit Runbook und Review |
| Sentinel | Ergänzt Defender XDR um SIEM-, SOAR- und Drittanbieter-Daten |
| MSSP | Übernimmt Monitoring und Analyse, interne IT liefert Kontext und Betriebsentscheidungen |
| Incident Closure | Erst nach vollständiger Bewertung, Remediation (Behebung) und Dokumentation |

---

## Vokabelliste

| Begriff | Kurzbeschreibung |
|---|---|
| Incident | Zusammenhängender Sicherheitsfall aus Alerts (Warnungen), Evidence (Beweise) und Assets (Bestand) |
| Alert (Warnung) | Einzelne sicherheitsrelevante Erkennung |
| Correlation | Automatisches Zusammenführen zusammengehöriger Signale |
| Incident Queue (Incidentwarteschlange) | Zentrale Liste der Incidents |
| Triage | Erste Priorisierung und Zuständigkeitsklärung |
| Severity (Schweregrad) | Technische Kritikalität |
| Priority (Priorität) | Tatsächliche Bearbeitungsreihenfolge unter Einbeziehung von Kontext |
| Status | Bearbeitungsstand eines Incidents |
| Assignment (Zuweisung) | Zuweisung an Bearbeiter oder Team |
| Classification (Klassifizierung) | Grundsätzliche Bewertung, z. B. True Positive (Richtig positiv) oder False Positive (Falsch positiv) |
| Determination (Bestimmung) | Genauere Ursache oder Art der Aktivität |
| Attack Story (Angriffsgeschichte) | Grafische und zeitliche Darstellung des Angriffsverlaufs |
| Alert Story (Warnungsverlauf) | Detaildarstellung eines Alerts (Warnungen) |
| Evidence (Beweise) | Datei, Prozess, E-Mail, URL oder anderes Untersuchungsobjekt |
| Entity (Entität) | Benutzer, Gerät, IP oder anderes sicherheitsrelevantes Objekt |
| Affected Asset (betroffene Ressource) | Betroffenes Gerät, Konto oder System |
| Verdict (Bewertung) | Bewertung einer Evidence (Beweise) |
| Device Page (Geräteseite) | Zentrale Defender-Ansicht eines Endpoints |
| Device Timeline (Gerätezeitachse) | Zeitliche Endpoint-Telemetrie |
| Parent Process (übergeordneter Prozess) | Prozess, der einen anderen Prozess gestartet hat |
| Child Process (untergeordneter Prozess) | Von einem Parent Process (übergeordneter Prozess) gestarteter Prozess |
| Command Line (Befehlszeile) | Aufrufparameter eines Prozesses |
| Advanced Hunting (Erweiterte Suche) | Proaktive Abfrage von Defender- und Sentinel-Daten |
| KQL | Kusto Query (Abfrage) Language |
| Schema | Tabellen- und Spaltenstruktur für Hunting Queries (Suchabfragen) |
| AlertInfo | Hunting (Bedrohungssuche)-Tabelle für Alert (Warnung)-Metadaten |
| AlertEvidence | Hunting (Bedrohungssuche)-Tabelle für Alert (Warnung)-Evidence (Beweise) |
| DeviceProcessEvents | Hunting (Bedrohungssuche)-Tabelle für Prozessstarts |
| DeviceNetworkEvents | Hunting (Bedrohungssuche)-Tabelle für Netzwerkverbindungen |
| DeviceFileEvents | Hunting (Bedrohungssuche)-Tabelle für Dateiaktivitäten |
| AIR | Automated Investigation and Response (Automatisierte Untersuchung und Reaktion) |
| Automated Investigation (Automatisierte Untersuchung) | Automatisierte Untersuchung eines Alerts (Warnungen) oder Geräts |
| Remediation (Behebung) | Beseitigung einer Bedrohung oder eines Artefakts |
| Pending Action (ausstehende Aktion) | Maßnahme wartet auf Freigabe |
| Action Center (Aktionscenter) | Zentrale Ansicht manueller und automatisierter Aktionen |
| Investigation Package (Untersuchungspaket) | Sammlung technischer Artefakte eines Geräts |
| Antivirus Scan (Antivirusscan) | Lokale Malware-Prüfung eines Geräts |
| Device Isolation (Geräteisolation) | Weitgehende Netzwerkisolation eines Geräts |
| Restrict App Execution | Einschränkung ausführbarer Anwendungen |
| Live Response (Liveantwort) | Remote-Shell für Untersuchung und Reaktion |
| Custom Detection (benutzerdefinierte Erkennung) | Eigene regelmäßige Erkennung auf Basis einer Hunting Query (Suchabfrage) |
| Detection Frequency (Erkennungshäufigkeit) | Ausführungsintervall einer Detection Rule (Erkennungsregel) |
| False Positive (Falsch positiv) | Legitime Aktivität wurde fälschlich als verdächtig erkannt |
| True Positive (Richtig positiv) | Tatsächlich sicherheitsrelevante oder bösartige Aktivität |
| MSSP | Managed Security Service Provider |
| SOC | Security Operations Center |
| SIEM | Security Information and Event Management |
| SOAR | Security Orchestration, Automation and Response |
| Microsoft Sentinel | Microsoft SIEM- und SOAR-Plattform |
| Escalation | Übergabe an eine zuständige oder höher priorisierte Stelle |
| Business Impact (betriebliche Auswirkung) | Betriebliche Auswirkung eines Incidents oder einer Maßnahme |
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
