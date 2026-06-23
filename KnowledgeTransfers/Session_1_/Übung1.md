## Übung 1: MDE-Onboarding-Policy in Intune finden

### Ziel

Die Teilnehmer sollen nachvollziehen können, wo das Onboarding zu Microsoft Defender for Endpoint für Windows-11-Clients konfiguriert ist.

### Schritte

1. Öffne das Intune Admin Center.
2. Navigiere zu:

   `Endpoint security` → `Endpoint detection and response`

3. Öffne die MDE/EDR-Onboarding-Policy für Windows 11.
4. Prüfe:
   - Policy-Name
   - Plattform
   - Profiltyp
   - Zuweisungen
   - Gerätestatus
   - Fehlgeschlagene Geräte
   - Ausgeschlossene Gruppen

### Diskussionsfragen

- Welche Geräte erhalten diese Policy?
- Gibt es Pilotgruppen oder Rollout-Wellen?
- Gibt es Geräte mit Fehlerstatus?
- Ist die Policy nur für Onboarding zuständig oder auch für AV/ASR/Firewall?

### Merksatz

Die EDR-Onboarding-Policy sorgt dafür, dass das Gerät zu Microsoft Defender for Endpoint onboarded wird. Sie ersetzt aber nicht die separaten Richtlinien für Defender Antivirus, ASR, Firewall, Security Baseline oder Exclusions.
