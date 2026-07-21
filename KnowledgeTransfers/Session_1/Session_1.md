# Knowledge Transfer Session 1  
## Orientierung nach der Migration – MDE, Intune und lokale Client-Validierung

## Ziel der Session

Die Teilnehmer sollen verstehen, wie Microsoft Defender for Endpoint, Microsoft Defender Antivirus, Intune und der lokale Windows-Client nach der Migration zusammenspielen.

Der Fokus liegt nicht auf einer allgemeinen Defender-Portal-Vorstellung, da Geräte- und Vulnerability-Ansichten bereits vorgestellt wurden. Stattdessen konzentriert sich diese Session auf:

- MDE-Onboarding über Intune
- Unterschied zwischen EDR-Onboarding und Defender Antivirus-Konfiguration
- Grundnavigation im Intune Admin Center
- Defender AV Passive Mode und Active Mode
- lokale Client-Validierung mit PowerShell
- praktische Orientierung für die interne IT nach der Migration

---

## Themen der Session

| Themenblock | Inhalt |
|---|---|
| Ziel der Session | Gemeinsames Verständnis schaffen, wie MDE-Onboarding, Defender Antivirus, Intune-Policies und lokale Clientprüfung zusammenhängen |
| Was ändert sich durch die Migration? | Wechsel von Trellix/McAfee zu Microsoft Defender Antivirus und Microsoft Defender for Endpoint; Unterschied zwischen AV-Ersatz und EDR-Onboarding |
| Komponentenüberblick | Microsoft Defender Antivirus; Microsoft Defender for Endpoint; Sense-Service; Intune; Defender Portal; Windows-Sicherheit |
| MDE-Onboarding über Intune | Erklärung der Intune EDR-Onboarding-Policy: was sie tut, was sie nicht tut, wie Zuweisung und Reporting funktionieren |
| Passive Mode vs. Active Mode | McAfee/Trellix aktiv = Defender AV typischerweise Passive Mode; McAfee/Trellix entfernt = Defender AV sollte Active/Normal Mode werden |
| Grundnavigation im Intune Portal | Devices; Endpoint Security; Antivirus; Endpoint Detection and Response; Policy Assignments; Device Status; Per-setting Status |
| Policy-Verständnis | Unterschied zwischen Onboarding Policy, AV Policy, ASR Policy, Firewall Policy, Security Baseline und Tamper Protection |
| Lokale Client-Validierung | PowerShell-Kommandos zur Prüfung von MDE-Onboarding, Sense-Service, AV-Modus, Signaturen und Policy-Werten |
| Praktische Orientierung | Teilnehmer sollen selbst Geräte finden, Policy-Status prüfen, PowerShell-Hilfe nutzen und Ergebnisse interpretieren |

---

# Kurzes Vokabeltraining

Die folgende Tabelle dient als roter Faden für den erklärenden Teil vor den praktischen Übungen.

| Nr. | Thema | Leitlinie / Kernaussage |
|---:|---|---|
| 1 | Ziel der Session | Erkennen, ob ein Windows-11-Client korrekt zu MDE onboarded ist und ob Defender Antivirus wie erwartet läuft |
| 2 | Ausgangslage beim Kunden | Windows-11-Clients werden über Intune verwaltet; bisher war McAfee/Trellix der aktive Virenschutz; Ziel ist Microsoft Defender for Endpoint mit Microsoft Defender Antivirus |
| 3 | Was ändert sich durch die Migration? | Nicht nur der Virenscanner wird ersetzt; auch Sichtbarkeit, Policy-Verwaltung und Betriebsmodell ändern sich |
| 4 | Microsoft Defender Antivirus | Lokaler Virenschutz auf dem Windows-Client für Echtzeitschutz, Security Intelligence, Cloud Protection, Scans, Remediation und Quarantäne |
| 5 | Microsoft Defender for Endpoint | Endpoint-Security- und EDR-Plattform für Geräteübersicht, Telemetrie, Alerts, Incidents, Timeline, Response Actions und Vulnerability-Informationen |
| 6 | Defender Antivirus vs. MDE | Defender Antivirus schützt lokal; MDE liefert EDR-Sichtbarkeit, Erkennung, Untersuchung und Reaktionsmöglichkeiten |
| 7 | Rolle von Intune | Zentrale Steuerung für Windows-11-Security-Policies wie EDR-Onboarding, Antivirus, ASR, Firewall, Security Baselines, Exclusions und Tamper Protection |
| 8 | EDR-Onboarding über Intune | Windows-11-Geräte werden über eine Intune Endpoint Detection and Response Policy zu Microsoft Defender for Endpoint onboarded |
| 9 | Was die EDR-Onboarding-Policy tut | MDE-Onboarding konfigurieren, Sense-Sensor anbinden und Gerätesichtbarkeit im Defender-Portal ermöglichen |
| 10 | Was die EDR-Onboarding-Policy nicht tut | Keine vollständige Security-Konfiguration; AV-, ASR-, Firewall-, Baseline-, Exclusion- und Hardening-Policies bleiben separate Richtlinien |
| 11 | Sense-Service | Microsoft Defender for Endpoint Sensor für EDR-Telemetrie, Defender-Portal-Sichtbarkeit, Timeline-Informationen und MDE-Anbindung |
| 12 | WinDefend-Service | Microsoft Defender Antivirus Service für lokale AV-Funktionalität auf dem Client |
| 13 | Passive Mode | Erwarteter Zustand während McAfee/Trellix als aktiver Drittanbieter-AV registriert ist; Defender AV ist vorhanden, aber nicht aktiver Echtzeitscanner |
| 14 | Active/Normal Mode | Zielzustand nach Entfernung oder Deaktivierung von McAfee/Trellix; Defender Antivirus übernimmt den Echtzeitschutz |
| 15 | Passive Mode bedeutet nicht automatisch ungeschützt | Während McAfee/Trellix aktiv ist, übernimmt McAfee/Trellix den primären AV-Schutz; nach McAfee-/Trellix-Removal wäre Passive Mode ein Problem |
| 16 | Typische Migrationszustände | Nicht onboarded; MDE-onboarded mit McAfee/Trellix aktiv; MDE-onboarded mit Defender AV aktiv; Fehlerzustände systematisch unterscheiden |
| 17 | Intune vs. Defender-Portal | Intune zeigt Management- und Policy-Sicht; Defender-Portal zeigt Security-Sicht, Sensorstatus, Alerts, Incidents, Exposure und Vulnerabilities |
| 18 | Warum beide Sichten wichtig sind | Migrationsvalidierung braucht Intune-Status, Defender-Portal-Sichtbarkeit und lokalen Clientstatus |
| 19 | Grundnavigation in Intune | Relevante Bereiche: Devices, Windows devices, Endpoint security, Antivirus, Endpoint detection and response, Attack surface reduction, Firewall und Security baselines |
| 20 | Endpoint Security Bereich | Zentraler Intune-Bereich für sicherheitsbezogene Windows-Richtlinien |
| 21 | Policy Assignments | Policies wirken über Include-/Exclude-Gruppen, Pilotgruppen, Rollout-Wellen und ggf. Scope Tags |
| 22 | Device Status und User Status | Intune-Policy-Status wie Success, Error, Pending oder Not applicable im Kontext von Assignment und letztem Check-in bewerten |
| 23 | Per-setting Status | Einstellungsspezifische Auswertung nutzen, um einzelne erfolgreiche oder fehlerhafte Policy-Werte zu erkennen |
| 24 | Policy-Konflikte | Konflikte durch mehrere Intune-Policies, Security Baselines oder bestehende GPOs erkennen und bereinigen |
| 25 | Einfluss von GPO und Hybrid-Umgebung | Bestehende Gruppenrichtlinien können in hybriden Umgebungen weiterhin Windows-, Defender- oder Security-Einstellungen beeinflussen |
| 26 | Tamper Protection | Schutz zentraler Defender-Einstellungen vor unbefugter lokaler Änderung durch Benutzer, Malware oder nicht autorisierte Prozesse |
| 27 | Windows-Sicherheit auf dem Client | Lokale Statusansicht für Viren- und Bedrohungsschutz, Schutzverlauf und Defender-Zustand; zentrale Verwaltung bleibt Intune |
| 28 | Lokale Prüfung mit PowerShell | Technischer Realitätscheck auf dem Client, besonders bei verzögertem oder unklarem Portalstatus |
| 29 | `Get-MpComputerStatus` | Aktuellen Defender-AV-Zustand prüfen: AV-Modus, Echtzeitschutz, Signaturen, NIS und Tamper Protection |
| 30 | `Get-MpPreference` | Lokal wirksame Defender-Konfiguration prüfen: Realtime Protection, PUA, Script Scanning, Sample Submission, Updatequellen und Exclusions |
| 31 | `Get-Service` | Dienste `Sense` und `WinDefend` prüfen und EDR-Sensor von Antivirus-Dienst unterscheiden |
| 32 | Signaturstatus | Aktualität der Defender-Schutzinformationen über Antivirus- und NIS-Signaturen bewerten |
| 33 | Network Inspection System | Defender-Komponente für netzwerk- und exploitbezogene Erkennungsmuster |
| 34 | Erwarteter Zustand vor McAfee-/Trellix-Removal | MDE-onboarded, Sense läuft, Defender AV häufig Passive Mode, Echtzeitschutz ggf. False, Signaturen aktuell |
| 35 | Erwarteter Zustand nach McAfee-/Trellix-Removal | Defender AV im Active/Normal Mode, Echtzeitschutz aktiv, Signaturen aktuell, Gerät weiterhin in MDE sichtbar |
| 36 | Typische Fehlerzustände | Gerät nicht im Defender-Portal sichtbar; Sense läuft nicht; Defender bleibt nach McAfee-Removal passiv; Signaturen veraltet; Intune-Policy fehlerhaft |
| 37 | Typische Ursachen für Probleme | Gruppenzuweisung, Intune Check-in, Netzwerk/Proxy, alte GPOs, McAfee-/Trellix-Reste, Dienste, Lizenz/Onboarding oder Policy-Konflikte prüfen |
| 38 | Warum nicht manuell konfigurieren? | PowerShell für Prüfung und Troubleshooting nutzen; produktive Defender-Konfiguration zentral über Intune steuern |
| 39 | Rolle des GitHub-Repos | Begleitmaterial für Übungen, Befehle, erwartete Werte, Merksätze, Troubleshooting-Hinweise und spätere Runbooks |
| 40 | Übergang zu den Übungen | Konzepte praktisch prüfen: Intune-Policy finden, Gerät suchen, Status interpretieren, PowerShell-Kommandos ausführen und Ergebnisse bewerten |