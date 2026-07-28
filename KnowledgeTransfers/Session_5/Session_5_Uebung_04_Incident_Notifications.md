# Session 5 – Übung 4
## Incident Notification Rule prüfen und Test-E-Mail senden

## Praxissituation

Ein High-Severity-Incident wurde außerhalb der Geschäftszeit erzeugt, aber das interne Team bemerkte ihn erst am nächsten Arbeitstag. Die vorhandene Notification Rule war entweder zu eng gefiltert oder an ein veraltetes Postfach adressiert.

Vor der Betriebsübergabe muss geprüft werden, ob kritische Incidentbenachrichtigungen zuverlässig an einen funktionierenden Verteiler gesendet werden.

## Ziel

Die Teilnehmer prüfen eine vorhandene Incident Notification Rule (Incidentbenachrichtigungsregel), validieren Severity, Device Scope und Empfänger und verwenden die integrierte Test-E-Mail-Funktion.

## Voraussetzungen

- Lesender Zugriff auf Microsoft Defender XDR Settings
- Für Änderungen oder neue Regeln: `Manage security settings` beziehungsweise Security Administrator oder gleichwertige Unified-RBAC-Berechtigung
- Freigegebene Test-E-Mail-Adresse oder Schulungsverteiler
- Keine produktive Notification Rule löschen

## Schritt-für-Schritt-Anleitung

### 1. Notification Settings öffnen

Navigiere zu:

```text
Microsoft Defender Portal
-> System
-> Settings (Einstellungen)
-> Microsoft Defender XDR
-> General (Allgemein)
-> Email notifications (E-Mail-Benachrichtigungen)
-> Incidents (Incidents)
```

### 2. Bestehende Regeln sichten

Prüfe für jede relevante Regel:

- Name und Description (Beschreibung),
- Enabled/Disabled (Aktiviert/Deaktiviert),
- Alert severity (Warnungsschweregrad),
- Device group scope (Gerätegruppenbereich),
- Recipients (Empfänger),
- `Send only one notification per incident`,
- Tenant-spezifischen Portal-Link,
- letzte fachliche Überprüfung.

Achte besonders auf:

- persönliche Einzelpostfächer statt Funktionsverteiler,
- ausgeschiedene Mitarbeiter,
- Regeln nur für Pilotgruppen,
- versehentliche Einschränkung auf falsche Device Group,
- doppelte Regeln mit identischen Empfängern.

### 3. Freigegebene Schulungsregel verwenden

Falls bereits eine Schulungsregel existiert, öffne sie und prüfe die Einstellungen.

Wenn die Teilnehmer Schreibrechte und eine ausdrückliche Freigabe besitzen, kann eine temporäre Regel vorbereitet werden:

```text
Rule name (Regelname): KT-Session5-Test-Incidents
Description (Beschreibung): Temporärer Test der Incidentbenachrichtigung
Severity: High
Device group scope: Pilot-/Testgerätegruppe
Recipient: freigegebenes Testpostfach
Send only one notification per incident: Enabled
```

Die Regel muss nicht produktiv gespeichert werden, um die Empfängerprüfung durchzuführen.

### 4. Test-E-Mail senden

Im Schritt `Recipients (Empfänger)`:

1. Testadresse eintragen.
2. `Add (Hinzufügen)` wählen.
3. `Send test email (Test-E-Mail senden)` auswählen.
4. Posteingang und gegebenenfalls Junk-/Spam-Ordner prüfen.
5. Kontrollieren, ob Absender, Tenant und Link plausibel sind.

### 5. Severity und Device Scope bewerten

Eine sinnvolle Regel für das interne Team könnte beispielsweise nur High-Severity-Incidents aus produktiven Windows-Client-Gruppen melden.

Prüfe jedoch, ob dadurch relevante Fälle außerhalb des Scopes verloren gehen, beispielsweise:

- Incident betrifft Benutzer oder E-Mail ohne MDE-Gerät,
- Gerät ist noch unter `Ungrouped devices (Nicht gruppierte Geräte)`,
- MSSP bearbeitet andere Device Groups,
- Medium-Severity-Incident betrifft privilegiertes Konto.

E-Mail-Benachrichtigungen ersetzen deshalb nicht die Incident Queue oder das MSSP-Monitoring.

### 6. Empfänger und Betriebsprozess prüfen

Der Empfänger sollte:

- ein gewartetes Funktionspostfach oder Verteiler sein,
- Vertreter und On-call-Prozess enthalten,
- regelmäßig getestet werden,
- zum vereinbarten Servicefenster passen,
- keine veralteten persönlichen Konten enthalten.

### 7. Regel nur bei Freigabe erstellen oder ändern

Kontrolliere auf der Seite `Review rule (Regel überprüfen)` alle Einstellungen.

Ohne ausdrückliche Freigabe:

```text
Nicht Create rule (Regel erstellen) wählen.
Wizard nach erfolgreicher Test-E-Mail schließen.
```

Mit Freigabe kann die temporäre Regel erstellt und nach dem Test kontrolliert wieder entfernt werden. Beachte, dass das Löschen einer Notification Rule dauerhaft ist.

## Kurze Zusammenfassung

Die Teilnehmer haben Incidentbenachrichtigungen auf Severity, Gerätescope und Empfänger geprüft und mit einer Test-E-Mail nachgewiesen, dass der vorgesehene Kommunikationsweg funktioniert.
