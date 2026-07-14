# Knowledge Transfer Session 3
## Operativer Security-Betrieb mit Microsoft Defender XDR

Dieser Ordner enthält die Schulungsunterlagen und acht praxisnahe Übungen für Session 3 des Microsoft-Defender-for-Endpoint-Migrationsprojekts.

## Kundenkontext

- ca. 1.500 Windows-11-Clients
- Verwaltung über Microsoft Intune
- Hybrid Entra ID / Active Directory
- Migration von McAfee/Trellix zu Microsoft Defender Antivirus
- Geräte sind über Intune zu Microsoft Defender for Endpoint onboarded
- Microsoft Defender Portal als zentrale XDR-Oberfläche
- spätere Einführung von Microsoft Sentinel
- mögliche Übernahme von Monitoring-Aufgaben durch einen MSSP

## Dateien

| Datei | Inhalt |
|---|---|
| `Session_3.md` | Erklärungsteil, Lernziele, Betriebsmodell, Tabellen, Zusammenfassung und Vokabelliste |
| `Session_3_Uebung_01_Incident_Triage_und_Priorisierung.md` | Incident Queue, Priorisierung, Status, Assignment und Alert Lifecycle |
| `Session_3_Uebung_02_Incident_Investigation_Evidence_Entities_Timeline.md` | Incident Story, Alerts, Evidence, Entities, Device Page und Timeline |
| `Session_3_Uebung_03_Advanced_Hunting_und_KQL.md` | KQL-Grundlagen und Suche nach ähnlichen Aktivitäten auf weiteren Geräten |
| `Session_3_Uebung_04_AIR_und_Action_Center.md` | Automated Investigation & Response, Verdicts, Pending Actions und History |
| `Session_3_Uebung_05_Response_Actions_und_Device_Isolation.md` | Auswahl geeigneter Response Actions und kontrollierte Geräteisolation |
| `Session_3_Uebung_06_Live_Response_auf_Testgeraet.md` | Sichere Live-Response-Untersuchung auf einem freigegebenen Testgerät |
| `Session_3_Uebung_07_Custom_Detection_Rule.md` | Aus einer Hunting Query eine Custom Detection Rule entwerfen |
| `Session_3_Uebung_08_MSSP_Sentinel_Eskalation_und_Abschluss.md` | Zusammenarbeit, Sentinel-Übergang, Eskalation, Dokumentation und Incident-Abschluss |

## Empfohlene Reihenfolge

1. Zuerst `Session_3.md` gemeinsam besprechen.
2. Übungen 1 bis 5 bilden den Pflichtkern für den täglichen Betrieb.
3. Übung 6 und 7 sind fortgeschritten und sollten nur mit geeigneten Rollen und Testsystemen durchgeführt werden.
4. Übung 8 dient als Abschluss und überführt die technischen Erkenntnisse in einen Betriebsprozess.

## Sicherheitshinweise

- Keine produktiven Response Actions ohne Freigabe ausführen.
- Geräteisolation, App-Restriktion, Datei-Quarantäne und Live Response können den Benutzer oder den Geschäftsbetrieb beeinflussen.
- Live Response nur auf einem ausdrücklich freigegebenen Testgerät oder im Rahmen eines bestätigten Incident-Response-Prozesses verwenden.
- Produktive Konfigurationsänderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.
- Alle Entscheidungen, Freigaben und Maßnahmen in einem Ticket oder Incident-Kommentar dokumentieren.

## Microsoft-Referenzen

- Incidents und Alerts: https://learn.microsoft.com/defender-xdr/incidents-overview
- Incident Management: https://learn.microsoft.com/defender-xdr/manage-incidents
- Incident Investigation: https://learn.microsoft.com/defender-xdr/investigate-incidents
- Advanced Hunting: https://learn.microsoft.com/defender-xdr/advanced-hunting-overview
- Automated Investigations: https://learn.microsoft.com/defender-endpoint/automated-investigations
- Response Actions: https://learn.microsoft.com/defender-endpoint/respond-machine-alerts
- Live Response: https://learn.microsoft.com/defender-endpoint/live-response
- Custom Detections: https://learn.microsoft.com/defender-xdr/custom-detection-rules
- Microsoft Sentinel im Defender Portal: https://learn.microsoft.com/azure/sentinel/microsoft-sentinel-defender-portal
