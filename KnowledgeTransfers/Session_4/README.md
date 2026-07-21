# Knowledge Transfer Session 4
## Policy Health, Vulnerability Management, Remediation und Threat Analytics

Dieser Ordner enthält den Erklärungsteil und sieben praxisnahe Übungen für Session 4 des Microsoft-Defender-for-Endpoint-Migrationsprojekts.


## Schwerpunkt der Session

Session 4 behandelt nicht erneut die Incident-Triage, Device Investigation, Automated Investigation & Response, Geräteisolation oder Live Response. Diese Themen wurden bereits in Session 3 behandelt.

Der Schwerpunkt liegt auf dem regelmäßigen Betrieb nach der Migration:

- Intune Policy Health und Konfliktanalyse
- Scan- und Updatezustände
- Exposure Management
- Security Recommendations
- Software Inventory und CVE-Bewertung
- Remediation Requests und Intune Security Tasks
- Exceptions und Risikoakzeptanz
- Threat Analytics und Betriebsreporting

## Dateien

| Datei | Inhalt |
|---|---|
| `Session_4.md` | Erklärungsteil, Lernziele, Betriebsmodell, Zusammenfassung und Vokabelliste |
| `Session_4_Uebung_01_Woechentlicher_Betriebscheck.md` | Wiederkehrender Betriebscheck in Defender XDR und Intune |
| `Session_4_Uebung_02_Intune_Policy_Konflikt.md` | Fehlerhafte oder widersprüchliche Endpoint-Security-Konfiguration untersuchen |
| `Session_4_Uebung_03_Security_Recommendation_Priorisieren.md` | Sicherheitsempfehlungen risikobasiert priorisieren |
| `Session_4_Uebung_04_Software_und_CVE_Untersuchen.md` | Softwarebestand und konkrete CVE tenantweit untersuchen |
| `Session_4_Uebung_05_Remediation_Request_Intune.md` | Remediation Request aus Defender an Intune übergeben und nachverfolgen |
| `Session_4_Uebung_06_Exception_und_Risikoakzeptanz.md` | Zeitlich begrenzte Ausnahme und kompensierende Maßnahmen bewerten |
| `Session_4_Uebung_07_Threat_Analytics_und_Reporting.md` | Aktuelle Bedrohung einordnen und einen Betriebsbericht ableiten |

## Empfohlene Reihenfolge

1. Zuerst `Session_4.md` gemeinsam besprechen.
2. Übungen 1 und 2 vermitteln den wiederkehrenden Intune-/Policy-Betrieb.
3. Übungen 3 bis 6 bilden den Vulnerability-Management- und Remediation-Workflow ab.
4. Übung 7 verbindet aktuelle Threat Intelligence mit dem Betriebsreporting.

## Portalbegriffe

Die Dateien verwenden das Format:

```text
English portal term (deutscher Portalbegriff)
```

Beispiel:

```text
Endpoint security (Endpunktsicherheit)
Exposure management (Risikoverwaltung)
Security recommendations (Sicherheitsempfehlungen)
Advanced hunting (Erweiterte Suche)
```

Microsoft ändert Portalnavigationen und Übersetzungen regelmäßig. Je nach Tenant-Rollout können einzelne Bezeichnungen geringfügig abweichen.

## Sicherheitshinweise

- Produktive Richtlinienänderungen nur über den freigegebenen Change-Prozess durchführen.
- Remediation Requests lösen nicht automatisch ein Update oder eine Deinstallation aus.
- Exceptions sind zeitlich zu begrenzen, zu genehmigen und regelmäßig zu überprüfen.
- Keine breite Ausnahme erstellen, wenn eine engere technische Lösung möglich ist.
- PowerShell dient in den Übungen primär zur Prüfung und Fehleranalyse.
- Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.

## Microsoft-Referenzen

- Security Recommendations: https://learn.microsoft.com/defender-vulnerability-management/tvm-security-recommendation
- Software Inventory: https://learn.microsoft.com/defender-vulnerability-management/tvm-software-inventory
- Remediation: https://learn.microsoft.com/defender-vulnerability-management/tvm-remediation
- Threat Analytics: https://learn.microsoft.com/defender-xdr/threat-analytics
- Intune Endpoint Security Policies: https://learn.microsoft.com/intune/device-configuration/endpoint-security/manage-policies
- Advanced Hunting TVM Tables: https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table
