# Session 4 – Übung 5
## Remediation Request aus Defender an Intune übergeben

## Praxissituation

Das Security-Team hat eine priorisierte Security Recommendation identifiziert: Eine verwundbare Software muss auf einer definierten Gruppe von Windows-11-Clients aktualisiert oder entfernt werden. Das Client-Team benötigt einen klaren Arbeitsauftrag mit Scope, Priorität, Frist und technischer Begründung.

Ein häufiger Fehler im Betrieb ist die Annahme, dass das Absenden einer Remediation Request die Änderung automatisch auf den Geräten ausführt. Tatsächlich beginnt damit ein koordinierter Workflow zwischen Defender Vulnerability Management und Intune.

## Ziel

Die Teilnehmer durchlaufen den Remediation-Workflow vom Defender Portal bis zur Intune Security Task und verstehen, wie die Umsetzung und Validierung erfolgen.

## Voraussetzungen

- Leserechte auf Security Recommendations
- für das tatsächliche Absenden geeignete Remediation-Berechtigung
- Zugriff auf Intune Security Tasks
- aktivierte Verbindung zwischen Defender for Endpoint und Intune
- keine produktive Übermittlung ohne Freigabe

## Schritt-für-Schritt-Anleitung

### 1. Intune-Verbindung prüfen

Im Defender Portal:

```text
System (System)
-> Settings (Einstellungen)
-> Endpoints (Endpunkte)
-> General (Allgemein)
-> Advanced features (Erweiterte Features)
```

Prüfe, ob die Microsoft Intune connection (Microsoft-Intune-Verbindung) aktiviert ist. Ohne diese Verbindung kann keine Intune Security Task erzeugt werden.

### 2. Sicherheitsempfehlung öffnen

Navigiere zu:

```text
Exposure management (Risikoverwaltung)
-> Recommendations (Empfehlungen)
-> <Sicherheitsempfehlung>
```

Prüfe vor dem Request:

- betroffene Software oder Konfiguration,
- Anzahl betroffener Geräte,
- verfügbare Abhilfe,
- Threat- und Exploit-Kontext,
- vorhandene Ausnahmen,
- Business-Abhängigkeiten.

### 3. Request remediation öffnen

Wähle:

```text
Request remediation (Wartung anfordern / Korrektur anfordern)
```

Je nach Portalübersetzung kann die Bezeichnung variieren.

### 4. Scope bewusst festlegen

Wähle nur den abgestimmten Gerätescope. Für einen echten Rollout sollte dies typischerweise sein:

```text
Pilotgruppe
-> technische Validierung
-> kontrollierte Rollout-Wellen
-> breite Produktion
```

Vermeide einen globalen Scope, wenn Anwendungskompatibilität oder Betriebswirkung noch nicht bewertet wurden.

### 5. Request-Informationen vervollständigen

Konfiguriere beziehungsweise prüfe:

- Priority (Priorität)
- Due date (Fälligkeitsdatum)
- Remediation type (Wartungs-/Korrekturtyp)
- Notes (Notizen)
- Create Intune security task (Intune-Sicherheitsaufgabe erstellen)
- betroffene Gerätegruppe oder Gerätemenge

Die Notiz sollte mindestens enthalten:

```text
Grund der Maßnahme
betroffene Software oder Einstellung
relevante CVE beziehungsweise Empfehlung
Pilot- und Rolloutanforderung
technisches Validierungskriterium
zuständiger App-/Client-Owner
Ticket- oder Change-Referenz
```

### 6. Vor Submit stoppen oder freigegeben absenden

In einer reinen Schulungsübung wird vor:

```text
Submit (Absenden)
```

abgebrochen.

Bei einem ausdrücklich freigegebenen Schulungsfall kann die Anforderung abgesendet werden.

### 7. Intune Security Task öffnen

Im Intune Admin Center:

```text
Endpoint security (Endpunktsicherheit)
-> Security tasks (Sicherheitsaufgaben)
```

Öffne die erzeugte Aufgabe und prüfe:

- Recommendation (Empfehlung)
- Status
- Priority (Priorität)
- Due date (Fälligkeitsdatum)
- affected devices (betroffene Geräte)
- Notes (Notizen)
- Security administrator context (Security-Administrator-Kontext)

### 8. Aufgabe akzeptieren und Umsetzung planen

Nur bei freigegebenem Workflow:

```text
Accept (Akzeptieren)
```

Die technische Umsetzung erfolgt danach über den passenden Intune-Mechanismus, zum Beispiel:

- Win32 app update,
- Microsoft Store app,
- Update Ring,
- Settings Catalog Policy,
- Endpoint Security Policy,
- Uninstall Assignment,
- Proactive Remediation beziehungsweise Remediations-Skript, wenn fachlich freigegeben.

Die Security Task selbst verändert das Gerät nicht.

### 9. Fortschritt nachverfolgen

Prüfe in Defender:

```text
Vulnerability management (Sicherheitsrisikoverwaltung)
-> Remediation (Wartung/Korrektur)
```

Beobachte:

- verbleibende betroffene Geräte,
- Fortschritt der Wartungsaktivität,
- überfällige Geräte,
- Geräte mit Offline- oder Installationsproblemen,
- mögliche Exceptions.

### 10. Abschluss technisch validieren

Eine Aufgabe wird erst abgeschlossen, wenn:

- die gewünschte Version oder Konfiguration tatsächlich vorhanden ist,
- die Anzahl gefährdeter Geräte sinkt,
- verbleibende Geräte erklärt oder ausgenommen sind,
- keine kritische Funktionsstörung entsteht,
- Ticket und Change aktualisiert wurden.

## Kurze Zusammenfassung

Die Teilnehmer haben den vollständigen Workflow von einer Security Recommendation über Request remediation bis zur Intune Security Task nachvollzogen. Sie wissen, dass der Request einen kontrollierten Arbeitsauftrag erzeugt, aber keine automatische Änderung an Endgeräten ausführt.
