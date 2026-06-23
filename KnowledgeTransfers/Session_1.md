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

## Roter Faden der Session

Die zentrale Leitfrage lautet:

> Wie erkennt die interne IT, ob ein Windows-11-Client korrekt per Intune zu Microsoft Defender for Endpoint onboarded ist, ob Microsoft Defender Antivirus noch passiv oder bereits aktiv läuft, und ob die relevanten Intune-Policies angekommen sind?

---
