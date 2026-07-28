# Knowledge Transfer Session 5
## Governance, Rollen, Audit und kontrollierter Policy-Betrieb

## Ziel der Session

Die Teilnehmer sollen verstehen, wie Microsoft Defender for Endpoint, Microsoft Defender XDR und Intune nach Abschluss der Migration dauerhaft sicher, nachvollziehbar und mit klaren Verantwortlichkeiten betrieben werden.

Der Schwerpunkt liegt auf der Frage:

```text
Wer darf welche Daten sehen und welche Aktionen ausführen,
wie wird eine Handlung nachgewiesen,
wie werden Benachrichtigungen zuverlässig zugestellt,
und wie wird eine Security-Policy geändert, ohne die gesamte Clientflotte zu gefährden?
```

Der zentrale Betriebsablauf lautet:

```text
Berechtigung nach Least Privilege vergeben
-> privilegierte Rechte bei Bedarf aktivieren
-> Aktion oder Änderung über freigegebenen Prozess durchführen
-> Wirkung auf Pilotgeräten validieren
-> Audit- und Portalstatus kontrollieren
-> gestuft ausrollen oder zurückrollen
-> Entscheidung und Ergebnis dokumentieren
```

---

## Lernziele

Nach dieser Session können die Teilnehmer:

- Microsoft Defender Unified RBAC einordnen,
- Intune RBAC, Defender Unified RBAC, Entra-Rollen und Azure RBAC unterscheiden,
- Permissions (Berechtigungen), Assignments (Zuweisungen), Data Sources (Datenquellen) und Device Groups (Gerätegruppen) gemeinsam bewerten,
- erklären, warum eine PIM-Aktivierung für einen Defender-Zugriff erforderlich sein kann,
- eine bestehende Rolle auf Least Privilege prüfen,
- typische Berechtigungsprobleme anhand von Symptom, Rolle und Data Scope eingrenzen,
- Response Actions und administrative Änderungen über Audit (Überwachung) nachvollziehen,
- Incident Notifications (Incidentbenachrichtigungen) prüfen und testen,
- Policy-Änderungen mit Pilotgruppe, Validierung, Rollout-Wellen und Rollback durchführen,
- Aufgaben zwischen Endpoint-Team, Security, Service Desk und MSSP abgrenzen,
- offene Risiken und Übergabepunkte für den späteren Regelbetrieb dokumentieren.

---

## 1. Warum Governance nach der Migration wichtig ist

Die technische MDE-Migration ist nur ein Teil des Zielzustands. Nach dem Projekt muss geregelt sein:

- wer Incidents und Alerts lesen darf,
- wer Incidents übernehmen und klassifizieren darf,
- wer Geräte isolieren oder Dateien remediieren darf,
- wer Live Response (Liveantwort) verwenden darf,
- wer AV-, ASR-, Firewall- und EDR-Policies ändern darf,
- wer Rollen und Berechtigungen verwaltet,
- wer außerhalb der Geschäftszeit benachrichtigt wird,
- wie Änderungen getestet und zurückgerollt werden,
- welche Aktionen ein MSSP ohne Rückfrage durchführen darf.

Ohne dieses Betriebsmodell entstehen typische Risiken:

- zu viele dauerhaft privilegierte Konten,
- unklare Zuständigkeit bei Incidents,
- nicht nachvollziehbare Response Actions,
- Änderungen direkt auf der Produktionsflotte,
- fehlende oder falsch adressierte Benachrichtigungen,
- widersprüchliche Zustände zwischen Defender, Intune und Ticketing.

---

## 2. Die wichtigsten Berechtigungsmodelle

| Berechtigungsmodell | Zuständigkeit | Beispiele |
|---|---|---|
| Microsoft Defender Unified RBAC | Daten und Aktionen im Microsoft Defender Portal | Incidents, Alerts, Response Actions, Hunting, Vulnerability Management, Live Response |
| Microsoft Intune RBAC | Geräteverwaltung und Endpoint-Security-Policies in Intune | Antivirus, ASR, Firewall, EDR, Security Baselines, Apps |
| Microsoft Entra Roles | tenantweite Administrator- und Reader-Funktionen | Security Reader, Security Operator, Security Administrator |
| Privileged Identity Management | zeitlich begrenzte Aktivierung privilegierter Rollen oder Gruppenmitgliedschaften | Security Administrator oder Mitgliedschaft in einer privilegierten Defender-Gruppe aktivieren |
| Azure RBAC | Azure-Ressourcen und später Microsoft Sentinel | Subscription, Resource Group, Log Analytics Workspace, Logic Apps |

### Wichtige Abgrenzung

Microsoft Defender Unified RBAC verwaltet **nicht** die Berechtigung zum Ändern von Intune Endpoint-Security-Policies. Diese Berechtigung bleibt im Intune Admin Center.

Beispiel:

```text
Defender Incident lesen und Gerät isolieren
-> Defender Unified RBAC

ASR-Policy von Audit auf Block ändern
-> Intune RBAC
```

---

## 3. Microsoft Defender Unified RBAC

Unified RBAC bietet eine zentrale Berechtigungsverwaltung für unterstützte Defender-Workloads.

Typischer Portalpfad:

```text
Microsoft Defender Portal
-> System
-> Permissions (Berechtigungen)
-> Microsoft Defender XDR
-> Roles (Rollen)
```

Eine Rolle besteht nicht nur aus einem Namen. Für die tatsächliche Wirkung sind mehrere Ebenen relevant:

| Ebene | Bedeutung |
|---|---|
| Role (Rolle) | Enthält die erlaubten Permissions |
| Permission group (Berechtigungsgruppe) | Security operations, Security posture oder Authorization and settings |
| Permission (Berechtigung) | Lesen oder Verwalten konkreter Daten und Aktionen |
| Assignment (Zuweisung) | Verbindet Rolle mit Benutzern oder Entra-Gruppen |
| Data source (Datenquelle) | Begrenzt die Rolle auf bestimmte Defender-Produkte oder Daten |
| Device group (Gerätegruppe) | Begrenzt Sichtbarkeit und Aktionen auf bestimmte MDE-Geräte |

### Typische Permission-Bereiche

| English term | Deutscher Begriff | Beispielwirkung |
|---|---|---|
| Security data basics – read | Sicherheitsdaten – Lesen | grundlegende Sicherheitsdaten ansehen |
| Alerts – manage | Warnungen – Verwalten | Alerts und Incidents bearbeiten |
| Response – manage | Reaktion – Verwalten | Response Actions ausführen |
| Basic live response – manage | Grundlegende Liveantwort – Verwalten | lesende Live-Response-Funktionen nutzen |
| Advanced live response – manage | Erweiterte Liveantwort – Verwalten | Skripte und eingreifende Funktionen verwenden |
| Vulnerability management – read | Sicherheitsrisikoverwaltung – Lesen | Vulnerability- und Exposure-Daten ansehen |
| Core security settings – manage | Zentrale Sicherheitseinstellungen – Verwalten | Defender-Sicherheitseinstellungen verwalten |
| System settings – read and manage | Systemeinstellungen – Lesen und verwalten | Portal- und Notification-Einstellungen ändern |
| Authorization – manage | Autorisierung – Verwalten | Rollen und Berechtigungen verwalten |

### Least Privilege

Die Rolle soll nur die Rechte enthalten, die für die Aufgabe notwendig sind.

Beispiele:

| Aufgabe | Nicht erforderlich |
|---|---|
| Incident lesen | Response Actions oder Rollenverwaltung |
| Incident bearbeiten | Advanced Live Response |
| Device Timeline prüfen | Intune-Policy-Schreibrechte |
| AV-/ASR-Policy ändern | Geräteisolation im Defender Portal |
| Audit Log lesen | Rollen- oder Systemeinstellungen ändern |

---

## 4. Bestehendes Rollenmodell des Kunden

Im Kundenkontext existieren die Gruppen:

```text
RL_Defender_Reader
RL_Defender_Operator
RL_Defender_Admin
```

Für den Betrieb muss bei jeder Gruppe geprüft werden:

1. Ist die Gruppe einer Entra-Rolle, einer Unified-RBAC-Rolle oder beiden zugewiesen?
2. Ist die Gruppenmitgliedschaft dauerhaft oder PIM-eligible?
3. Welche Defender-Permissions enthält die Rolle tatsächlich?
4. Welche Data Sources sind ausgewählt?
5. Welche Device Groups darf die Gruppe sehen und verwalten?
6. Welche Funktionen verbleiben getrennt in Intune RBAC?

**Merksatz:** Ein verständlicher Gruppenname beweist noch nicht, welche effektiven Berechtigungen ein Benutzer besitzt.

---

## 5. PIM und zeitlich begrenzter Zugriff

Privileged Identity Management kann zwei unterschiedliche Aktivierungen betreffen:

- Aktivierung einer Microsoft-Entra-Rolle,
- Aktivierung einer berechtigten Mitgliedschaft in einer privilegierten Entra-Gruppe.

Wenn eine Unified-RBAC-Rolle einer Gruppe zugewiesen ist und der Benutzer nur **eligible (berechtigt)** für diese Gruppe ist, wird der Defender-Zugriff erst wirksam, nachdem die Gruppenmitgliedschaft über PIM aktiviert wurde.

Typischer Ablauf:

```text
Benutzer ist eligible für RL_Defender_Operator
-> PIM-Aktivierung starten
-> MFA / Begründung / Approval, abhängig von Policy
-> Gruppenmitgliedschaft wird temporär aktiv
-> Defender-RBAC-Zuweisung greift
-> Portal neu laden oder neue Sitzung öffnen
```

### Gründe für PIM

- keine dauerhaften hohen Rechte,
- nachvollziehbare Aktivierung,
- MFA und Begründung,
- optionaler Approval-Prozess,
- zeitliche Begrenzung,
- Auditierbarkeit.

---

## 6. Device Groups und Data Scope

Eine Permission kann korrekt sein, aber trotzdem keine Daten oder Aktionen für ein bestimmtes Gerät erlauben.

Microsoft Defender for Endpoint Device Groups werden separat verwaltet und begrenzen:

- welche Geräte sichtbar sind,
- welche Geräte untersucht werden dürfen,
- auf welchen Geräten Response Actions ausgeführt werden dürfen.

Typischer Pfad:

```text
System
-> Settings (Einstellungen)
-> Endpoints (Endpunkte)
-> Permissions (Berechtigungen)
-> Device groups (Gerätegruppen)
```

Prüffragen:

- Befindet sich das Gerät in der erwarteten Device Group?
- Ist die Unified-RBAC-Assignment auf diese Gruppe begrenzt?
- Greift eine Rangfolge oder Regel anders als erwartet?
- Ist das Gerät noch unter `Ungrouped devices (Nicht gruppierte Geräte)`?
- Hat das MSSP nur den vertraglich vereinbarten Scope?

---

## 7. Intune RBAC

Für die Verwaltung von Endpoint-Security-Policies bleibt Intune das maßgebliche Berechtigungsmodell.

Typische Rollen:

| Rolle | Verwendung |
|---|---|
| Endpoint Security Manager | AV-, ASR-, EDR-, Firewall- und Baseline-Policies verwalten |
| Read Only Operator | Geräte und Konfigurationen lesen |
| Intune Role Administrator | Intune-Rollen und -Zuweisungen verwalten |
| Custom Intune Role | gezielte Least-Privilege-Berechtigung mit Scope Groups und Scope Tags |

Intune verwendet zusätzlich:

- Scope Groups,
- Scope Tags,
- Assignments,
- Include-/Exclude-Gruppen.

Ein Benutzer kann daher im Defender Portal weitreichende Rechte besitzen und trotzdem keine Intune-Policy ändern dürfen – oder umgekehrt.

---

## 8. Audit und Nachvollziehbarkeit

Microsoft Defender XDR und Microsoft Defender for Endpoint protokollieren zahlreiche Administrator- und Benutzeraktionen im Microsoft-365-Audit-Log.

Beispiele:

- Geräteisolation,
- Freigabe aus der Isolation,
- Erstellung oder Änderung von Rollen,
- Erstellung oder Änderung von Custom Detections,
- Zuweisung eines Incidents,
- Änderung bestimmter Portal- und Sicherheitseinstellungen.

Typischer Pfad:

```text
Microsoft Defender Portal
-> System
-> Audit (Überwachung)
```

Alternativ kann Microsoft Purview Audit verwendet werden.

### Wichtige Audit-Felder

| Feld | Bedeutung |
|---|---|
| Date/Time | Zeitpunkt der Aktion |
| User | ausführender Benutzer oder Dienst |
| Activity | ausgeführte Aktion |
| Workload | betroffener Microsoft-Dienst |
| Target | betroffenes Gerät, Incident oder Objekt |
| Result | Erfolg oder Fehler |
| Additional details | weitere IDs und technische Details |

### Audit vs. Action Center

| Audit | Action Center |
|---|---|
| Nachweis von Benutzer- und Adminaktivitäten | Übersicht manueller und automatisierter Security Actions |
| Purview-/Microsoft-365-Auditbasis | Defender-XDR-Betriebsansicht |
| Rollenänderungen und administrative Aktionen | Remediation, Quarantäne, Isolation und Pending Actions |
| Compliance- und Nachweisfokus | Security-Operations-Fokus |

---

## 9. Incident Notifications

Incident Notifications verhindern, dass kritische Incidents nur im Portal sichtbar bleiben.

Portalpfad:

```text
System
-> Settings (Einstellungen)
-> Microsoft Defender XDR
-> General (Allgemein)
-> Email notifications (E-Mail-Benachrichtigungen)
-> Incidents (Incidents)
```

Eine Notification Rule kann unter anderem filtern nach:

- Alert severity (Warnungsschweregrad),
- Device group scope (Gerätegruppenbereich),
- einer oder mehreren Empfängeradressen,
- nur einer Nachricht pro Incident,
- tenant-spezifischem Portal-Link.

### Betriebsanforderungen

- gemeinsames Funktionspostfach oder belastbarer Verteiler,
- Vertretung und On-call-Prozess,
- regelmäßiger Test,
- dokumentierte Severity-Schwelle,
- passende Device Groups,
- Abgleich mit MSSP- und ITSM-Benachrichtigungen,
- Vermeidung mehrfacher widersprüchlicher Meldungen.

---

## 10. Change Management für Security Policies

Eine Änderung an AV-, ASR-, Firewall- oder EDR-Policies ist ein Security Change und sollte nicht unmittelbar auf alle 1.500 Geräte wirken.

Empfohlener Ablauf:

```text
Änderungsbedarf identifizieren
-> bestehende Telemetrie und Business-Auswirkung bewerten
-> Change und Owner festlegen
-> Pilotpolicy oder begrenztes Pilotassignment verwenden
-> Testgerät synchronisieren
-> Intune- und lokalen Ist-Zustand validieren
-> Benutzer- und App-Owner-Feedback prüfen
-> Rollout-Wellen freigeben
-> technische Wirkung überwachen
-> abschließen oder zurückrollen
```

### Trennung von Policy und Assignment

Zwei Möglichkeiten:

1. Bestehende Policy ändern und zunächst nur kleine Pilotgruppe zuweisen.
2. Separate Pilotpolicy mit klarer Benennung verwenden und nach Validierung in Produktionspolicy überführen.

Für kritische Änderungen ist eine separate Pilotpolicy häufig leichter nachvollziehbar.

---

## 11. Pilot-, Rollout- und Rollback-Modell

| Phase | Zweck |
|---|---|
| Lab/Test | technische Grundfunktion ohne produktiven Benutzer prüfen |
| IT Pilot | Support-, Admin- und IT-nahe Geräte prüfen |
| Business Pilot | ausgewählte Fachbereiche und reale Anwendungen validieren |
| Rollout Wave | kontrolliert größere Geräteanzahl einbeziehen |
| Production | freigegebener Zielzustand |

### Rollback muss vor dem Change definiert sein

Beispiele:

- ASR-Regel von Block zurück auf Audit,
- Pilotassignment entfernen,
- vorherige Policyversion wiederherstellen,
- Ausschluss nur nach Security-Freigabe ergänzen,
- betroffene Anwendung oder Gerät aus der Welle nehmen,
- Change stoppen und Incidents/Alerts auswerten.

**Merksatz:** „Wir setzen es wieder zurück“ ist kein Rollback-Plan. Der konkrete technische Weg, Owner und Auslösekriterien müssen vorher feststehen.

---

## 12. Manuelle Verfahrensanweisung, Runbook und Playbook

| Begriff | Bedeutung |
|---|---|
| Bearbeitungsablauf / Verfahrensanweisung | dokumentierte manuelle Schritte für Analysten oder IT |
| Azure Automation Runbook | ausführbares Automatisierungsskript oder Workflow |
| Microsoft Sentinel Playbook | Logic-App-basierter automatisierter Response-Workflow |
| Automation Rule | Sentinel-Regel zum Zuweisen, Taggen oder Starten eines Playbooks |

Für Session 5 ist besonders wichtig: Zuerst muss der manuelle Ablauf korrekt sein. Erst danach sollten sichere und wiederkehrende Schritte automatisiert werden.

---

## 13. MSSP- und Sentinel-Readiness

Auch ohne eigene Übung bleiben diese Themen Teil der Betriebsübergabe.

### MSSP

Zu klären sind:

- welche Incidents der MSSP bearbeitet,
- welche Aktionen ohne Rückfrage erlaubt sind,
- welche Device Groups sichtbar sind,
- wer Isolation, Live Response oder Identity Response freigibt,
- wo der führende Bearbeitungsstatus gepflegt wird,
- welche Reaktionszeit außerhalb der Geschäftszeit gilt.

### Microsoft Sentinel

Für die spätere Einführung sind vorzubereiten:

- Workspace- und Azure-RBAC-Modell,
- priorisierte Datenquellen,
- Aufbewahrung und Kosten,
- gemeinsame Incident Queue im Defender Portal,
- Analytics Rules,
- Automation Rules und Playbooks,
- MSSP- und ITSM-Anbindung.

---

## 14. Betriebsübergabe und Abschlusskriterien

Die Migration ist erst betriebsbereit, wenn mindestens folgende Punkte geklärt sind:

- MDE-Onboarding und Defender-AV-Zielzustand sind validiert,
- Trellix-Decommissioning ist dokumentiert,
- AV-, ASR-, EDR-, Firewall- und Baseline-Policies sind dokumentiert,
- Rollen und PIM-Prozess sind getestet,
- Notification Rules funktionieren,
- Audit- und Action-Center-Nachweise sind zugänglich,
- Change- und Rollback-Prozess ist definiert,
- Bearbeitungs- und Eskalationswege sind freigegeben,
- offene Exceptions und Remediations besitzen Owner und Termin,
- MSSP- und Sentinel-Folgeaktivitäten sind dokumentiert.

---

## Zusammenfassung

| Thema | Kernaussage |
|---|---|
| Unified RBAC | Steuert Defender-Daten und -Aktionen zentral und granular |
| Intune RBAC | Bleibt für Endpoint-Security-Policies und Geräteverwaltung zuständig |
| PIM | Reduziert dauerhafte privilegierte Berechtigungen |
| Device Groups | Begrenzen Gerätesichtbarkeit und Response Actions |
| Audit | Macht Benutzer-, Admin- und Response-Aktivitäten nachvollziehbar |
| Notifications | Stellen sicher, dass kritische Incidents die richtigen Empfänger erreichen |
| Change Management | Verhindert unkontrollierte Änderungen an der gesamten Clientflotte |
| Pilotierung | Validiert technische und fachliche Auswirkungen vor dem Rollout |
| Rollback | Muss vor dem Change technisch und organisatorisch definiert sein |
| MSSP | Benötigt klaren Scope, Freigaben und lokalen Business-Kontext |
| Sentinel | Erweitert Defender XDR später um weitere Datenquellen und SOAR |
| Betriebsübergabe | Benötigt Technik, Rollen, Prozesse, Nachweise und offene Risiken |

---

## Vokabelliste

| Begriff | Kurzbeschreibung |
|---|---|
| RBAC | Role-Based Access Control; rollenbasierte Zugriffssteuerung |
| Unified RBAC | Zentrales Defender-Berechtigungsmodell |
| Permission | Einzelne Berechtigung zum Lesen oder Verwalten |
| Role | Sammlung von Berechtigungen |
| Assignment | Zuweisung einer Rolle an Benutzer oder Gruppen |
| Data Source | Datenquelle beziehungsweise Defender-Workload im Role Scope |
| Data Scope | Datenbereich, auf den eine Rolle wirkt |
| Device Group | MDE-Gerätegruppe zur Eingrenzung von Sichtbarkeit und Aktionen |
| Least Privilege | Nur die minimal erforderlichen Rechte vergeben |
| Entra Role | Tenantweite Administrator- oder Reader-Rolle |
| PIM | Privileged Identity Management |
| Eligible | Berechtigt, eine Rolle oder Gruppenmitgliedschaft zu aktivieren |
| Active Assignment | Aktuell wirksame Rollen- oder Gruppenmitgliedschaft |
| Intune RBAC | Berechtigungsmodell für Intune-Verwaltung |
| Scope Group | Benutzer-/Gerätescope einer Intune-Rollenzuweisung |
| Scope Tag | Sichtbarkeits- und Verwaltungskennzeichnung in Intune |
| Security Reader | Lesende Sicherheitsrolle |
| Security Operator | Rolle für operative Security-Aufgaben |
| Security Administrator | Hochprivilegierte Rolle für Sicherheitseinstellungen |
| Audit Log | Protokoll administrativer und sicherheitsrelevanter Aktionen |
| Action Center | Defender-Übersicht manueller und automatisierter Security Actions |
| Incident Notification Rule | E-Mail-Regel für neue oder aktualisierte Incidents |
| Change | Kontrollierte Änderung an einer produktiven Konfiguration |
| Pilot Group | Kleine, kontrollierte Testgruppe |
| Rollout Wave | Gestufte Ausbringungsgruppe |
| Rollback | Definierte technische Rücknahme einer Änderung |
| Security Baseline | Microsoft- oder organisationsbasierte Sammlung von Security Settings |
| Settings Catalog | Intune-Profil für einzelne Windows-Einstellungen |
| Endpoint Security Policy | Intune-Policy für AV, ASR, Firewall, EDR und weitere Security-Bereiche |
| Bearbeitungsablauf | Dokumentierte manuelle Schritte für einen Betriebsfall |
| Runbook | Automatisierter Azure-Automation-Ablauf oder je nach Kontext standardisierte Betriebsanweisung |
| Playbook | Sentinel-/Logic-App-basierter automatisierter Ablauf |
| Automation Rule | Sentinel-Regel zum Steuern von Incident-Automation |
| MSSP | Managed Security Service Provider |
| SLA | Vereinbarte Service- und Reaktionszeit |
| Residual Risk | Nach Maßnahmen verbleibendes Restrisiko |
| Operational Handover | Formale Übergabe vom Projekt in den Regelbetrieb |

---

## Microsoft-Referenzen

- https://learn.microsoft.com/defender-xdr/manage-rbac
- https://learn.microsoft.com/defender-xdr/custom-permissions-details
- https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles
- https://learn.microsoft.com/defender-xdr/activate-defender-rbac
- https://learn.microsoft.com/defender-xdr/compare-rbac-roles
- https://learn.microsoft.com/defender-xdr/microsoft-xdr-auditing
- https://learn.microsoft.com/defender-xdr/m365d-notifications-incidents
- https://learn.microsoft.com/intune/intune-service/fundamentals/role-based-access-control
- https://learn.microsoft.com/intune/intune-service/protect/endpoint-security-policy
