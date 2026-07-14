# Session 3 - Übung 1
## Incident-Triage und Priorisierung

## Praxissituation

Am Montagmorgen befinden sich mehrere neue Incidents in der Defender Incident Queue. Ein Incident betrifft ein normales Bürogerät mit Medium Severity. Ein anderer Incident betrifft das Notebook eines Administrators und enthält Hinweise auf Credential Access. Das MSSP hat noch keine Bearbeitung übernommen.

Die interne IT muss entscheiden, welcher Incident zuerst bearbeitet wird, wer zuständig ist und welche Informationen sofort gesammelt werden müssen.

## Ziel der Übung

Die Teilnehmer sollen einen neuen Incident strukturiert triagieren, priorisieren, zuweisen und für die weitere Investigation vorbereiten.

## Benötigte Berechtigungen

- Leserechte auf Incidents und Alerts im Microsoft Defender Portal
- Für Assignment, Status, Tags und Kommentare entsprechende Incident-Management-Rechte
- Zugriff auf Geräte- und Benutzerinformationen

## Ausgangspunkt

```text
https://security.microsoft.com
```

Typischer Pfad:

```text
Investigation & response -> Incidents & alerts -> Incidents
```

Die Bezeichnungen können sich durch Portalupdates geringfügig ändern.

## Aufgabe

Wähle einen ungefährlichen Test-, Demo- oder bereits abgeschlossenen Incident und führe eine vollständige Ersttriage durch.

Beantworte:

- Warum wurde der Incident priorisiert?
- Welche Alerts gehören zum Incident?
- Welche Assets sind betroffen?
- Ist die Aktivität noch aktiv?
- Welche Person oder welches Team übernimmt?
- Welche nächsten Schritte sind erforderlich?

## Schritt-für-Schritt-Anleitung

### 1. Incident Queue öffnen

1. Öffne die Incident Queue.
2. Setze einen geeigneten Zeitraum, beispielsweise 7 oder 30 Tage.
3. Prüfe Filter für Severity, Status, Service Source und Assignment.
4. Sortiere nach Priorität oder Zeitpunkt.

### 2. Incident-Grunddaten dokumentieren

| Feld | Beobachtung |
|---|---|
| Incident Name |  |
| Incident ID |  |
| Created Time |  |
| Last Updated |  |
| Severity |  |
| Status |  |
| Assigned to |  |
| Service Sources |  |
| Anzahl Alerts |  |
| Betroffene Geräte |  |
| Betroffene Benutzer |  |

### 3. Triage-Fragen beantworten

| Prüffrage | Beobachtung | Auswirkung auf Priorität |
|---|---|---|
| Ist die Aktivität noch aktiv? |  |  |
| Gibt es Credential-Theft-Hinweise? |  |  |
| Gibt es laterale Bewegung? |  |  |
| Sind mehrere Geräte betroffen? |  |  |
| Ist ein privilegierter Benutzer betroffen? |  |  |
| Ist das Gerät geschäftskritisch? |  |  |
| Wurde bereits blockiert oder isoliert? |  |  |
| Gibt es Pending Actions? |  |  |

### 4. Incident priorisieren

Ordne den Incident ein:

| Priorität | Beispiel |
|---|---|
| Kritisch | Aktive Kompromittierung, Credential Theft, laterale Bewegung, Datenabfluss |
| Hoch | Wahrscheinliche Kompromittierung ohne bestätigte Ausbreitung |
| Normal | Verdächtige Aktivität, weitere Untersuchung erforderlich |
| Niedrig | Erwartete Aktivität, Test oder wahrscheinlicher False Positive |

### 5. Bearbeitung vorbereiten

Falls in der Schulungsumgebung erlaubt:

1. Setze den Status auf `In progress`.
2. Weise den Incident einem Schulungsbenutzer oder Team zu.
3. Ergänze einen Tag, beispielsweise `KnowledgeTransfer-Session3`.
4. Füge einen Kommentar hinzu.

Beispiel:

```text
Ersttriage durchgeführt. Incident betrifft ein Windows-11-Pilotgerät.
Keine bestätigte Ausbreitung. Device Timeline und Alert Evidence werden geprüft.
Keine Response Action ohne weitere Freigabe.
```

## KQL-Ergänzung

Alerts der letzten sieben Tage nach Quelle und Severity zusammenfassen:

```kql
AlertInfo
| where Timestamp > ago(7d)
| summarize AlertCount=count() by ServiceSource, DetectionSource, Severity
| order by AlertCount desc
```

Häufigste Alerttitel:

```kql
AlertInfo
| where Timestamp > ago(30d)
| summarize AlertCount=count(),
            FirstSeen=min(Timestamp),
            LastSeen=max(Timestamp)
  by Title, Severity, ServiceSource
| order by AlertCount desc
```

## Diskussionsfragen

- Warum ist Severity allein nicht ausreichend?
- Welche Incidents darf die interne IT selbst bearbeiten?
- Wann muss das MSSP sofort eingebunden werden?
- Wer darf einen Incident schließen?
- Welche Informationen kann nur die interne IT liefern?

## Merksatz

Triage bedeutet nicht, den Incident bereits vollständig zu lösen. Triage schafft schnell Klarheit über Risiko, Reihenfolge, Zuständigkeit und nächste Schritte.
