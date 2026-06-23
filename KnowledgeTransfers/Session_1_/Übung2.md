## Übung 2: EDR-Onboarding-Policy vs. Defender Antivirus Policy

### Ziel

Wir wollen verstehen, dass MDE-Onboarding und Defender Antivirus-Konfiguration zwei unterschiedliche Themen sind.

### Aufgabe (Testgerät = W11PC9610)

Vergleiche in Intune:

1. Die EDR-Onboarding-Policy unter:

   `Endpoint security` → `Endpoint detection and response`

2. Die Defender Antivirus Policy unter:

   `Endpoint security` → `Antivirus`

### Prüfpunkte

| Frage | Beobachtung |
|---|---|
| Welche Policy onboarded das Gerät zu MDE? |  |
| Welche Policy konfiguriert Defender Antivirus? |  |
| Wo wird Realtime Protection konfiguriert? |  |
| Wo wird PUA Protection konfiguriert? |  |
| Wo werden ASR-Regeln konfiguriert? |  |
| Wo werden Firewall-Regeln konfiguriert? |  |
| Wo wird Tamper Protection konfiguriert? |  |

### Merksatz

MDE-Onboarding und Defender Antivirus-Konfiguration sind verwandt, aber nicht dasselbe.  
Die EDR-Onboarding-Policy bringt das Gerät in Microsoft Defender for Endpoint.  
Die AV-Policy steuert die lokalen Defender-Antivirus-Einstellungen.