# Session 5 – Übung 1
## Microsoft Defender Unified RBAC: bestehende Rolle und Zuweisung prüfen

## Praxissituation

Nach der Aktivierung von Microsoft Defender Unified RBAC wurden beim Kunden die Gruppen `RL_Defender_Reader`, `RL_Defender_Operator` und `RL_Defender_Admin` vorgesehen. Ein neuer Mitarbeiter soll Incidents lesen und untersuchen, aber keine Geräte isolieren, keine Live-Response-Skripte ausführen und keine Rollen verwalten.

Vor der Zuweisung muss geprüft werden, welche der vorhandenen Rollen diese Anforderung tatsächlich erfüllt. Der Gruppenname allein ist kein ausreichender Nachweis.

## Ziel

Die Teilnehmer prüfen eine bestehende Unified-RBAC-Rolle vollständig: Permissions (Berechtigungen), Assigned users and groups (zugewiesene Benutzer und Gruppen), Data Sources (Datenquellen) sowie den zugehörigen Device Scope (Gerätebereich).

## Voraussetzungen

- Lesender Zugriff auf `Permissions (Berechtigungen)` und `Roles (Rollen)` im Microsoft Defender Portal
- Unified RBAC ist für die relevanten Workloads aktiviert
- Kenntnis der vorhandenen Gruppen `RL_Defender_Reader`, `RL_Defender_Operator` und `RL_Defender_Admin`
- In der Übung keine Rolle ändern oder neu zuweisen

## Schritt-für-Schritt-Anleitung

### 1. Unified-RBAC-Rollen öffnen

Navigiere zu:

```text
Microsoft Defender Portal
-> System
-> Permissions (Berechtigungen)
-> Microsoft Defender XDR
-> Roles (Rollen)
```

Prüfe, ob auf der Seite ein Hinweis zu nicht aktivierten Workloads erscheint. Öffne `Workload settings (Workloadeinstellungen)` nur lesend und kontrolliere, welche Defender-Workloads bereits Unified RBAC verwenden.

### 2. Eine vorhandene Rolle öffnen

Öffne nacheinander die Rollen beziehungsweise Assignments, die zu folgenden Gruppen gehören:

```text
RL_Defender_Reader
RL_Defender_Operator
RL_Defender_Admin
```

Falls die Gruppen nicht direkt als Rollenname erscheinen, öffne die vorhandenen Custom Roles (benutzerdefinierten Rollen) und suche im Bereich `Assignments (Zuweisungen)` nach den Gruppen.

### 3. Grunddaten der Rolle prüfen

Kontrolliere:

- Role name (Rollenname),
- Description (Beschreibung),
- Created by (Erstellt von),
- Last modified (Zuletzt geändert),
- Anzahl der Assignments (Zuweisungen).

Achte darauf, ob Beschreibung und tatsächliche Berechtigungen zusammenpassen.

### 4. Permissions untersuchen

Öffne die Permission Groups (Berechtigungsgruppen):

```text
Security operations (Sicherheitsvorgänge)
Security posture (Sicherheitsstatus)
Authorization and settings (Autorisierung und Einstellungen)
```

Prüfe bei der Reader-/Leser-Rolle insbesondere:

- Security data basics – read,
- Alerts – read beziehungsweise fehlendes Manage-Recht,
- Hunting-/Raw-Data-Zugriff, sofern vorgesehen,
- Vulnerability management – read.

Prüfe, dass folgende eingreifende Rechte **nicht** versehentlich enthalten sind, wenn die Rolle nur lesen und untersuchen soll:

- Response – manage,
- Basic live response – manage,
- Advanced live response – manage,
- File collection – manage,
- Authorization – manage,
- System settings – read and manage.

### 5. Assignment prüfen

Öffne:

```text
Assignments (Zuweisungen)
```

Kontrolliere:

- welche Entra-Benutzer oder -Gruppen zugewiesen sind,
- ob nur Security Groups verwendet werden,
- ob eine Gruppe versehentlich mehreren Rollen mit zusätzlichen Rechten zugewiesen ist,
- welche Data Sources (Datenquellen) ausgewählt sind.

### 6. Data Sources prüfen

Kontrolliere, ob die Zuweisung beispielsweise auf folgende Quellen begrenzt ist:

```text
Microsoft Defender for Endpoint
Microsoft Defender for Office 365
Microsoft Defender for Identity
Microsoft Defender Vulnerability Management
```

Für einen Endpoint-orientierten Reader muss nicht automatisch jede Defender-Datenquelle freigegeben sein.

### 7. Device Group Scope prüfen

Navigiere typischerweise zu:

```text
System
-> Settings (Einstellungen)
-> Endpoints (Endpunkte)
-> Permissions (Berechtigungen)
-> Device groups (Gerätegruppen)
```

Prüfe:

- in welcher Device Group die Pilot- und Produktionsclients landen,
- welche Entra-Gruppe Zugriff auf die jeweilige Device Group besitzt,
- ob die Reader-/Operator-Gruppe nur den vorgesehenen Scope sieht,
- ob Geräte unerwartet unter `Ungrouped devices (Nicht gruppierte Geräte)` erscheinen.

### 8. Ergebnis anhand des Anwendungsfalls bewerten

Für den beschriebenen Mitarbeiter ist die Rolle geeignet, wenn er:

- Incidents, Alerts, Devices und Timeline lesen kann,
- die notwendigen Hunting- oder Untersuchungsdaten sehen kann,
- keine Response Actions ausführen kann,
- keine Live-Response-Session mit erweiterten Befehlen starten kann,
- keine Rollen, System- oder Security-Einstellungen ändern kann,
- nur die vorgesehenen Device Groups sieht.
