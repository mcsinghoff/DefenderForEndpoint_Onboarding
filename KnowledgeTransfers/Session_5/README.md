# Knowledge Transfer Session 5
## Governance, Rollen, Audit und kontrollierter Policy-Betrieb

Dieser Ordner enthält die Schulungsunterlagen und fünf praxisnahe Übungen für Session 5 des Microsoft-Defender-for-Endpoint-Migrationsprojekts.

## Kundenkontext

- ca. 1.500 Windows-11-Clients
- Verwaltung über Microsoft Intune
- Hybrid Entra ID / Active Directory
- Migration von McAfee/Trellix zu Microsoft Defender Antivirus
- Geräte sind über Intune zu Microsoft Defender for Endpoint onboarded
- Microsoft Defender Portal als zentrale XDR-Oberfläche
- Microsoft Defender Unified RBAC ist für den Berechtigungsbetrieb relevant
- privilegierte Rollen beziehungsweise Gruppen können über Privileged Identity Management aktiviert werden
- spätere Einführung von Microsoft Sentinel
- mögliche Übernahme von Monitoring-Aufgaben durch einen MSSP

## Schwerpunkt der Session

Session 5 schließt die Knowledge-Transfer-Reihe ab und behandelt den kontrollierten Regelbetrieb:

- Microsoft Defender Unified RBAC verstehen und Rollen prüfen
- Intune RBAC, Defender RBAC, Entra-Rollen und PIM unterscheiden
- Berechtigungsprobleme systematisch untersuchen
- eingreifende Aktionen über Audit Logs nachvollziehen
- Incident Notifications (Incidentbenachrichtigungen) testen
- Änderungen an AV-, ASR-, Firewall- oder EDR-Policies kontrolliert pilotieren und zurückrollen
- Rollen, Audit, Change Management, MSSP- und Sentinel-Readiness in ein Betriebsmodell überführen

## Enthaltene Dateien

| Datei | Inhalt |
|---|---|
| `Session_5.md` | Erklärungsteil, Rollenmodell, Audit, Notifications, Change Management, Betriebsübergabe, Zusammenfassung und Vokabelliste |
| `Session_5_Uebung_01_Unified_RBAC_Rolle_Pruefen.md` | Bestehende Unified-RBAC-Rolle, Zuweisung, Berechtigungen und Device Scope untersuchen |
| `Session_5_Uebung_02_Berechtigungsproblem_Analysieren.md` | Ursache fehlender Portalansichten oder Aktionen über PIM, Unified RBAC, Device Groups und Intune RBAC eingrenzen |
| `Session_5_Uebung_03_Defender_Audit_Log.md` | Ausführenden Benutzer und Ablauf einer Response Action im Audit Log nachvollziehen |
| `Session_5_Uebung_04_Incident_Notifications.md` | Incident Notification Rule prüfen und mit Test-E-Mail validieren |
| `Session_5_Uebung_05_Policy_Change_und_Rollback.md` | ASR-Policy auf Pilotgerät ändern, lokal validieren und kontrolliert zurückrollen |





## Sicherheitshinweise

- Rollen, Notification Rules und produktive Endpoint-Security-Policies nur mit ausdrücklicher Freigabe ändern.
- Keine produktive Geräteisolation, Datei-Quarantäne oder andere Response Action nur zu Schulungszwecken ausführen.
- Übung 5 ausschließlich mit vorbereiteter Pilotpolicy, Pilotgruppe und freigegebenem Testgerät durchführen.
- Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Microsoft Defender Portal und nicht lokal per PowerShell.
- Aktionen, Rollenänderungen und Policy-Changes müssen durch Ticket, Change oder Incident-Kommentar nachvollziehbar sein.

## Microsoft-Referenzen

- Unified RBAC: https://learn.microsoft.com/defender-xdr/manage-rbac
- Unified RBAC Permissions: https://learn.microsoft.com/defender-xdr/custom-permissions-details
- Create Custom Roles: https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles
- Activate Unified RBAC: https://learn.microsoft.com/defender-xdr/activate-defender-rbac
- Permission Mapping: https://learn.microsoft.com/defender-xdr/compare-rbac-roles
- Defender Audit: https://learn.microsoft.com/defender-xdr/microsoft-xdr-auditing
- Incident Notifications: https://learn.microsoft.com/defender-xdr/m365d-notifications-incidents
- Intune RBAC: https://learn.microsoft.com/intune/intune-service/fundamentals/role-based-access-control
- Intune Endpoint Security Policies: https://learn.microsoft.com/intune/intune-service/protect/endpoint-security-policy
