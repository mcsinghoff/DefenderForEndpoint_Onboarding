# Session 3 - Übung 8
## MSSP-/Sentinel-Eskalation und Incident-Abschluss

## Praxissituation

Das MSSP meldet einen Incident mit MDE-Prozessdaten. Zusätzlich existieren Hinweise aus einer Firewall und aus Entra-Anmeldedaten. Microsoft Sentinel ist beim Kunden noch nicht vollständig eingeführt, soll diese Datenquellen aber zukünftig in der einheitlichen Defender-Oberfläche zusammenführen.

Die interne IT muss heute schon festlegen, welche Informationen sie an das MSSP liefert, wer Response Actions (Antwortaktionen) freigibt und wann ein Incident geschlossen werden darf.

## Ziel der Übung

Die Teilnehmer sollen einen technischen Incident in einen vollständigen Betriebs- und Eskalationsprozess überführen und die spätere Rolle von Microsoft Sentinel einordnen.

## Benötigte Berechtigungen

- Leserechte auf Incident, Alerts (Warnungen) und Geräte
- Zugriff auf das interne Ticketsystem oder eine Schulungsvorlage
- Keine produktiven Sentinel- oder Response-Konfigurationen erforderlich

## Aufgabe

Bearbeite ein Beispiel mit folgenden Informationen:

```text
- MDE Alert (Warnung): verdächtige PowerShell-Ausführung
- Gerät: Windows-11-Client eines Administrators
- Netzwerkhinweis: Verbindung zu unbekannter IP-Adresse
- Benutzerhinweis: ungewöhnliche Anmeldung kurz vor dem Alert (Warnung)
- MSSP-Empfehlung: Gerät isolieren und Zugangsdaten zurücksetzen
```

Erstelle:

- Eskalationsentscheidung,
- Rollen- und Verantwortlichkeitsmatrix,
- Kommunikationsvorlage,
- Abschlusskriterien,
- Liste der später in Sentinel benötigten Datenquellen.

## Schritt-für-Schritt-Anleitung

### 1. Technische Fakten gedanklich sammeln

| Feld | Wert |
|---|---|
| Incident ID (Incident-ID) |  |
| Incident Title (Incidenttitel) |  |
| Severity (Schweregrad)/Priority (Priorität) |  |
| Betroffenes Gerät |  |
| Betroffener Benutzer |  |
| Prozesskette |  |
| Remote IP/URL |  |
| Weitere Geräte |  |
| Bereits erfolgte Aktionen |  |
| Pending Actions (ausstehende Aktionen) |  |

### 2. Business-Kontext gedanklich ergänzen ergänzen

| Frage | Antwort |
|---|---|
| Ist der Benutzer privilegiert? |  |
| Ist das Gerät geschäftskritisch? |  |
| Welche Anwendungen und Daten sind betroffen? |  |
| Ist ein Ersatzgerät verfügbar? |  |
| Welcher Fachbereich muss informiert werden? |  |
| Bestehen Melde- oder Datenschutzpflichten? |  |

### 3. Verantwortlichkeiten festlegen - Beispielsweise durhc RACI Matrix (Auch diese nur als Beispiel, kann bei jedem Unternehmen anders aussehen)

| Tätigkeit | MSSP/SOC | Interne IT | Fachbereich/Management |
|---|---|---|---|
| 24/7 Monitoring | R | I | I |
| Ersttriage | R | C | I |
| Lokalen Benutzerkontext liefern | C | R | C |
| Isolation empfehlen | R | C | I |
| Isolation freigeben | C | R/A je nach Prozess | C/I |
| Kennwort-/Token-Reset | C | R | I |
| Geräte-Rebuild | C | R | I |
| Datenschutzbewertung | C | C | R/A |
| Incident-Abschluss | C | R/A | I |

Legende:

- `R` = Responsible
- `A` = Accountable
- `C` = Consulted
- `I` = Informed

### 4. Eskalationsstufen definieren

| Stufe | Beispiel | Reaktion |
|---|---|---|
| 1 | Einzelner Low (Niedrig)/Medium (Mittel) Alert (Warnung) ohne Folgeaktivität | Interne Triage, normale Bearbeitung |
| 2 | Wahrscheinliche Kompromittierung eines Clients | MSSP/Security einbinden, Response Action (Antwortaktion) prüfen |
| 3 | Privilegiertes Konto, Credential Theft oder mehrere Geräte | Sofortige Eskalation, Isolation und Identity Response |
| 4 | Datenabfluss, Ransomware oder kritische Infrastruktur | Krisen-/Major-Incident-Prozess, Management und weitere Stellen |

### 5. MSSP-Übergabe: Notwendige Daten isolieren

Beispiel:

```text
Incident: <ID und Titel>
Priorität: <Wert>
Betroffene Assets (Bestand): <Gerät und Benutzer>
Business-Kontext: <Rolle/Kritikalität>
Technische Beobachtung: <Prozesskette, Hash, IP/URL>
Bereits durchgeführt: <Aktionen>
Aktueller Status: <isoliert/nicht isoliert, online/offline>
Offene Entscheidung: <z. B. Isolation, Live Response (Liveantwort), Kennwortreset>
Freigaben: <Name/Rolle/Ticket>
Gewünschte Unterstützung: <konkrete Frage an MSSP>
```


### 8. Wenn nötig, in Ticket Abschlusskommentar erstellen

```text
Incident als <Classification (Klassifizierung)> / <Determination (Bestimmung)> bewertet.
Betroffen waren <Assets (Bestand)>.
Root Cause (Grundursache): <Ursache>.
Durchgeführte Maßnahmen: <Liste>.
Scope-Prüfung: <Ergebnis>.
Validierung: <Nachweis>.
Restrisiko: <Bewertung>.
Folgeaufgaben: <Tickets/Changes>.
Freigabe zum Abschluss durch <Rolle/Name> am <Datum>.
```

## KQL-Ergänzung
< leer >

## PowerShell-Ergänzung

< leer >

## Diskussionsfragen

- Welche Entscheidungen darf das MSSP ohne Rückfrage treffen?
- Wie schnell muss die interne IT außerhalb der Geschäftszeit reagieren?
- Welche Datenquellen haben für die Sentinel-Einführung höchste Priorität?
- Wo wird der führende Bearbeitungsstatus gepflegt: Defender Incident oder ITSM-Ticket?
- Wie verhindert man doppelte oder widersprüchliche Dokumentation?

## Merksatz

Ein Incident ist erst dann betrieblich beherrscht, wenn technische Analyse, Business-Kontext, Verantwortlichkeiten, Maßnahmen und Abschlussnachweise zusammengeführt wurden.
