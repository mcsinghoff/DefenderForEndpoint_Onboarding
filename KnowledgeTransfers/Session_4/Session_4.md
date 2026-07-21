# Knowledge Transfer Session 4
## Policy Health, Vulnerability Management, Remediation und Threat Analytics

## Ziel der Session

Die Teilnehmer sollen lernen, wie Microsoft Defender XDR und Microsoft Intune nach der Migration von McAfee/Trellix für den proaktiven und wiederkehrenden Security-Betrieb genutzt werden.

Der Schwerpunkt liegt nicht auf der Bearbeitung eines aktiven Incidents. Stattdessen geht es um die Fragen:

```text
Werden die vorgesehenen Sicherheitsrichtlinien korrekt angewendet?
Welche Konfigurationsfehler oder Konflikte bestehen?
Welche Software und Schwachstellen erhöhen das Risiko?
Welche Security Recommendations müssen zuerst umgesetzt werden?
Wie wird aus einer Empfehlung eine nachvollziehbare Remediation in Intune?
Wie werden nicht sofort behebbare Risiken kontrolliert und dokumentiert?
Welche aktuellen Bedrohungen sind für den eigenen Tenant relevant?
```

Der operative Grundablauf lautet:

```text
Zustand prüfen
-> Abweichung oder Risiko erkennen
-> technischen und geschäftlichen Kontext bewerten
-> Owner und Maßnahme festlegen
-> Remediation über Intune umsetzen
-> Fortschritt validieren
-> Ausnahme oder Restrisiko dokumentieren
-> Ergebnis berichten
```

---

## Lernziele

Nach dieser Session können die Teilnehmer:

- einen wiederkehrenden Betriebscheck in Defender XDR und Intune durchführen,
- Scan-, Update- und Policy-Zustände sinnvoll einordnen,
- Intune Policy Errors (Richtlinienfehler) und Conflicts (Konflikte) untersuchen,
- lokale Defender-Werte mit zentralen Intune-Vorgaben vergleichen,
- Security Recommendations (Sicherheitsempfehlungen) risikobasiert priorisieren,
- Software Inventory (Softwareinventar) und CVE-Daten untersuchen,
- Advanced Hunting (Erweiterte Suche) für Vulnerability-Management-Fragen verwenden,
- einen Remediation Request (Wartungsanforderung) an Intune übergeben,
- Intune Security Tasks (Sicherheitsaufgaben) und Remediation Activities (Wartungsaktivitäten) nachverfolgen,
- zeitlich begrenzte Exceptions (Ausnahmen) mit kompensierenden Maßnahmen bewerten,
- Threat Analytics (Bedrohungsanalyse) auf den eigenen Tenant beziehen,
- einen verständlichen Betriebsbericht für IT, Security, Management und MSSP erstellen.

---

## Portalhinweis

In den Unterlagen werden wichtige Portalbegriffe zweisprachig angegeben:

```text
English portal term (deutscher Portalbegriff)
```

Die genaue Navigation kann sich aufgrund von Portalupdates oder Preview-Rollouts unterscheiden. Insbesondere Funktionen von Defender Vulnerability Management können je nach Tenant unter unterschiedlichen Navigationspfaden erscheinen.

---

## 1. Betriebsmodell nach der Migration

Nach der Migration ist Security Operations nicht nur die Reaktion auf Incidents. Ein wesentlicher Teil des Betriebs besteht darin, Schutzlücken früh zu erkennen und zu beseitigen.

| Betriebsbereich | Typische Frage | Zuständige Plattform |
|---|---|---|
| Policy Health (Richtlinienzustand) | Werden die vorgesehenen Einstellungen auf allen Zielgeräten angewendet? | Intune |
| Scan and Update State (Scan- und Updatezustand) | Sind Security Intelligence, Plattform und Scans aktuell? | Defender Portal, Intune, PowerShell |
| Vulnerability Management (Sicherheitsrisikoverwaltung) | Welche Schwachstellen und Fehlkonfigurationen erhöhen das Risiko? | Defender Portal |
| Remediation (Wartung/Korrektur) | Wer setzt die Maßnahme um und bis wann? | Defender Portal, Intune |
| Exceptions (Ausnahmen) | Welches Risiko kann vorübergehend nicht behoben werden? | Defender Portal, Ticket-/Change-Prozess |
| Threat Analytics (Bedrohungsanalyse) | Welche aktuellen Kampagnen oder Schwachstellen betreffen den Tenant? | Defender Portal |
| Reporting (Berichterstellung) | Wie wird der Zustand für Stakeholder verständlich dargestellt? | Defender Portal, Intune, ITSM/Reporting |

### Rollen im Betriebsmodell

| Rolle | Typische Verantwortung |
|---|---|
| Security-Team oder MSSP | Risiko erkennen, Empfehlungen priorisieren, Threat Context liefern |
| Client-/Workplace-Team | Richtlinien, Updates, Software und Konfigurationen über Intune umsetzen |
| App-Owner | Kompatibilität und Business-Abhängigkeiten bewerten |
| Service Desk | Benutzerkontext, Gerätestatus und lokale Auswirkungen aufnehmen |
| Management/Risk Owner | Fristen, Prioritäten und Risikoakzeptanzen genehmigen |

**Merksatz:** Defender identifiziert das Risiko. Intune setzt viele der notwendigen Änderungen um. Der Prozess braucht trotzdem Owner, Frist und Validierung.

---

## 2. Scan- und Updatezustände

Auch ohne einen eigenen AV-Health-Schwerpunkt müssen im Betrieb wichtige Aktualitätswerte verstanden werden.

| Bereich | Bedeutung |
|---|---|
| Security Intelligence (Sicherheitsinformationen) | Aktuelle Erkennungsdaten und Signaturen |
| Engine (Engine) | Scan- und Erkennungslogik von Defender Antivirus |
| Platform (Plattform) | Defender-Dienste und Produktkomponenten |
| Quick Scan (Schnellscan) | Prüfung typischer Malware- und Persistenzorte |
| Full Scan (Vollständiger Scan) | Umfangreiche Prüfung des Systems; nicht regelmäßig für alle Clients erforderlich |
| Signature Update Interval (Intervall für Sicherheitsinformationsupdates) | Wie häufig nach neuen Schutzinformationen gesucht wird |
| Fallback Order (Fallbackreihenfolge) | In welcher Reihenfolge Updatequellen kontaktiert werden |

### Typische Betriebsabweichungen

- Security Intelligence ist mehrere Tage veraltet.
- Geräte erreichen Microsoft Update oder MMPC nicht.
- Eine alte WSUS-/GPO-Konfiguration verhindert den gewünschten Updatepfad.
- Geplante Scans laufen auf mobilen Geräten nicht zum erwarteten Zeitpunkt.
- Intune zeigt eine erfolgreiche Policy, lokal ist der Wert dennoch anders.

**Merksatz:** Ein erfolgreiches Policy Deployment (Richtlinienbereitstellung) beweist nicht automatisch, dass der lokale Schutzwert aktuell und wirksam ist.

---

## 3. Intune Policy Health

Microsoft Intune ist für die Windows-11-Geräte die zentrale Konfigurationsplattform. Relevante Bereiche sind:

```text
Endpoint security (Endpunktsicherheit)
-> Antivirus (Antivirus)
-> Endpoint detection and response (Endpunkterkennung und -reaktion)
-> Attack surface reduction (Verringerung der Angriffsfläche)
-> Firewall (Firewall)
-> Security baselines (Sicherheitsbaselines)
```

### Wichtige Statuswerte

| English term | Deutscher Begriff | Bedeutung |
|---|---|---|
| Succeeded | Erfolgreich | Policy wurde verarbeitet; lokale Wirksamkeit bei Bedarf zusätzlich prüfen |
| Error | Fehler | Einstellung konnte nicht korrekt angewendet werden |
| Conflict | Konflikt | Mehrere Quellen setzen widersprüchliche Werte |
| Pending | Ausstehend | Gerät hat die Änderung noch nicht vollständig verarbeitet oder nicht eingecheckt |
| Not applicable | Nicht zutreffend | Policy passt nicht auf Plattform, Profil oder Scope |

### Relevante Ansichten

- Assignments (Zuweisungen)
- Device status (Gerätestatus)
- User status (Benutzerstatus)
- Per-setting status (Status pro Einstellung)
- Deployment report (Bereitstellungsbericht)

**Merksatz:** Bei Fehlern immer zuerst Scope, Assignment, Check-in und den Status der konkreten Einstellung prüfen.

---

## 4. Policy-Konflikte und Konfigurationsquellen

Eine Defender-Einstellung kann aus unterschiedlichen Quellen stammen:

- Endpoint security policy (Endpunktsicherheitsrichtlinie)
- Security baseline (Sicherheitsbaseline)
- Settings catalog profile (Einstellungskatalogprofil)
- Device configuration profile (Gerätekonfigurationsprofil)
- Group Policy (Gruppenrichtlinie)
- lokale Konfiguration
- MDE Security Settings Management (MDE-Verwaltung von Sicherheitseinstellungen)

### Typische Konfliktursachen

| Ursache | Beispiel |
|---|---|
| Zwei Intune-Policies | Eine Policy aktiviert, eine andere deaktiviert dieselbe Defender-Einstellung |
| Baseline und Einzelpolicy | Security Baseline setzt einen anderen Wert als die AV-Policy |
| GPO und MDM | Alte Gruppenrichtlinie überschreibt oder beeinflusst den gewünschten MDM-Wert |
| Falsche Zuweisung | Gerät erhält Pilot- und Produktionspolicy gleichzeitig |
| Veralteter Status | Portal zeigt alten Wert, weil das Gerät länger nicht synchronisiert hat |
| Tamper Protection | Nicht autorisierte oder lokale Änderung wird nicht wirksam |
| Trellix-Reste | Drittanbieter-AV ist noch registriert und beeinflusst Defender-Zustand |

### Troubleshooting-Reihenfolge

```text
1. Zielwert bestimmen.
2. Alle möglichen Konfigurationsquellen identifizieren.
3. Assignments und Ausschlüsse prüfen.
4. Per-setting status kontrollieren.
5. Gerät synchronisieren.
6. lokalen Ist-Zustand prüfen.
7. GPO- und Event-Log-Einfluss bewerten.
8. nur die ursächliche Konfigurationsquelle korrigieren.
```

---

## 5. Lokales Troubleshooting

PowerShell ist ein wichtiges Diagnosewerkzeug. Sie ersetzt nicht die zentrale Konfiguration.

### Defender-Zustand und Einstellungen

```powershell
Get-MpComputerStatus
Get-MpPreference
Get-Service -Name Sense, WinDefend -ErrorAction SilentlyContinue
```

### Defender-Konfigurationsänderungen im Event Log

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Windows Defender/Operational'
    Id        = 5007
    StartTime = (Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Id, Message
```

### MDM-Diagnoseereignisse

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' -MaxEvents 100 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message
```

### Gruppenrichtlinienbericht

```powershell
gpresult /h "$env:TEMP\gpresult.html"
```

> Produktive Änderungen erfolgen zentral über Intune beziehungsweise das Defender Portal und nicht lokal per PowerShell.

---

## 6. Exposure Management

Exposure Management (Risikoverwaltung) hilft, technische Schwächen im Kontext der tatsächlichen Gefährdung zu bewerten.

Es beantwortet nicht nur:

```text
Welche Schwachstelle existiert?
```

sondern auch:

```text
Wie wahrscheinlich ist eine Ausnutzung?
Welche Assets sind betroffen?
Welchen Geschäftswert besitzen diese Assets?
Gibt es aktive Threat Campaigns (Bedrohungskampagnen)?
Welche Maßnahme reduziert das Risiko am stärksten?
```

### Wichtige Kennzahlen

| Begriff | Bedeutung |
|---|---|
| Exposure score (Gefährdungsscore) | Gesamtbild der organisatorischen Gefährdung |
| Secure Score for Devices (Microsoft-Sicherheitsbewertung für Geräte) | Umsetzungsgrad sicherheitsrelevanter Gerätekonfigurationen |
| Exposed devices (Verfügbargemachte/gefährdete Geräte) | Geräte, die von einem Risiko betroffen sind |
| Critical assets (Kritische Ressourcen) | Geräte oder Systeme mit erhöhtem Geschäftswert |
| EPSS | Wahrscheinlichkeit, dass eine CVE in einem definierten Zeitraum ausgenutzt wird |

**Merksatz:** CVSS beschreibt technische Schwere. Priorität entsteht erst aus Schwere, Exploit-Kontext, Asset-Kritikalität und Business Impact.

---

## 7. Security Recommendations

Security recommendations (Sicherheitsempfehlungen) übersetzen erkannte Schwächen in konkrete Maßnahmen.

Mögliche Empfehlungen:

- Software aktualisieren,
- nicht mehr unterstützte Software entfernen,
- Defender-Sicherheitsfunktion aktivieren,
- unsichere Protokolle oder Konfigurationen deaktivieren,
- Browser oder Runtime härten,
- fehlende Security Updates bereitstellen.

### Priorisierungskriterien

| Kriterium | Warum wichtig? |
|---|---|
| Active threat (Aktive Bedrohung) | Risiko ist bereits in aktuellen Kampagnen relevant |
| Exploit available (Exploit verfügbar) | Angreifer können die Schwachstelle leichter ausnutzen |
| Zero-day tag (Zero-Day-Markierung) | Keine oder nur eingeschränkte reguläre Abhilfe vorhanden |
| Number of exposed devices (Anzahl gefährdeter Geräte) | Bestimmt den technischen Scope |
| Asset criticality (Ressourcenkritikalität) | Admin- und kritische Geräte erhöhen die Priorität |
| Internet exposure (Internetexposition) | Externe Erreichbarkeit erhöht das Risiko |
| Remediation effort (Umsetzungsaufwand) | Schnelle Maßnahmen können eine hohe Risikoreduktion bieten |
| Business dependency (Geschäftsabhängigkeit) | Update oder Entfernung kann Fachprozesse beeinflussen |

### Fehler bei der Priorisierung

- ausschließlich nach CVSS sortieren,
- ausschließlich nach Anzahl der Geräte sortieren,
- Empfehlungen ohne App-Owner-Kontext umsetzen,
- Security Score als alleinige Zielgröße verwenden,
- Empfehlungen schließen, bevor die technische Wirkung validiert wurde.

---

## 8. Software Inventory

Software Inventory (Softwareinventar) zeigt bekannte Softwareprodukte, Versionen, Hersteller und betroffene Geräte.

Mögliche Pfade im Defender Portal:

```text
Exposure management (Risikoverwaltung)
-> Vulnerability management (Sicherheitsrisikoverwaltung)
-> Inventories (Bestände)
-> Software (Software)
```

Je nach Tenant-Rollout kann der Bereich noch unter Endpoints (Endpunkte) oder einer älteren Vulnerability-Management-Navigation erscheinen.

### Typische Betriebsfragen

- Wo ist eine bestimmte Software installiert?
- Welche Versionen sind vorhanden?
- Welche Versionen sind verwundbar?
- Ist die Software End of Support (Ende des Supports)?
- Welche Geräte sind besonders kritisch?
- Gibt es Evidence (Nachweise) aus Registry oder Dateisystem?
- Ist ein Update, eine Entfernung oder eine Einschränkung möglich?

### Grenzen

Software Inventory ist kein vollständiger Ersatz für Software Asset Management. Nicht jede Anwendung wird gleich detailliert unterstützt, und einzelne Software kann nur auf Geräteebene mit begrenzten Informationen sichtbar sein.

---

## 9. Vulnerability Investigation

Eine Schwachstellenuntersuchung verbindet:

- CVE-ID,
- CVSS und dynamische Risikofaktoren,
- Exploit-Verfügbarkeit,
- betroffene Softwareversionen,
- betroffene Geräte,
- empfohlene Security Updates,
- Tenant- und Threat-Kontext.

### Relevante Hunting-Tabellen

| Tabelle | Zweck |
|---|---|
| `DeviceTvmSoftwareInventory` | installierte Softwareprodukte und Versionen |
| `DeviceTvmSoftwareVulnerabilities` | Schwachstellen je Gerät und Software |
| `DeviceTvmSoftwareVulnerabilitiesKB` | CVE-Wissensbasis, CVSS, Exploit-Verfügbarkeit und Beschreibung |

### Beispielquery: kritische Schwachstellen

```kql
DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel =~ 'Critical'
| summarize AffectedDevices=dcount(DeviceId),
            Devices=make_set(DeviceName, 20),
            Versions=make_set(SoftwareVersion, 20)
  by CveId, SoftwareVendor, SoftwareName,
     RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| order by AffectedDevices desc
```

### Beispielquery: Exploit-Verfügbarkeit ergänzen

```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(30d) or isnotempty(DeviceId)
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | project CveId, CvssScore, IsExploitAvailable,
              PublishedDate, VulnerabilityDescription
) on CveId
| summarize AffectedDevices=dcount(DeviceId),
            Versions=make_set(SoftwareVersion, 20)
  by CveId, SoftwareVendor, SoftwareName,
     VulnerabilitySeverityLevel, CvssScore, IsExploitAvailable,
     RecommendedSecurityUpdate
| order by IsExploitAvailable desc, AffectedDevices desc
```

Hinweis: TVM-Tabellen sind in Defender XDR Advanced Hunting verfügbar. Ihre direkte Nutzung in Microsoft Sentinel kann je nach Tabelle und Integrationsmodell eingeschränkt sein.

---

## 10. Remediation über Intune

Ein Remediation Request (Wartungsanforderung) verbindet Security und IT Operations.

Typischer Pfad:

```text
Exposure management (Risikoverwaltung)
-> Recommendations (Empfehlungen)
-> <Sicherheitsempfehlung öffnen>
-> Request remediation (Wartung anfordern / Korrektur anfordern)
```

### Was geschieht beim Absenden?

- In Defender wird eine Remediation Activity (Wartungsaktivität) erstellt.
- Bei aktivierter Intune-Verbindung kann eine Intune Security Task (Intune-Sicherheitsaufgabe) erzeugt werden.
- Das Client-Team bewertet und implementiert die technische Änderung.
- Die Anforderung selbst aktualisiert oder deinstalliert keine Software.
- Fortschritt und Abschluss werden anschließend nachverfolgt.

### Notwendige Angaben

- betroffene Geräte oder Gerätegruppen,
- Priorität,
- gewünschte Maßnahme,
- Fälligkeitsdatum,
- Begründung,
- IT-/App-Owner,
- Pilot- und Rolloutvorgehen,
- Validierungskriterium.

**Merksatz:** Ein Remediation Request ist ein Arbeitsauftrag, kein automatischer Patch-Mechanismus.

---

## 11. Remediation Tracking

Eine Maßnahme gilt nicht als abgeschlossen, nur weil eine Policy oder Anwendung in Intune bereitgestellt wurde.

### Phasen

```text
Requested (Angefordert)
-> Accepted (Akzeptiert)
-> Implementation in pilot (Umsetzung im Pilot)
-> Broad deployment (Breite Bereitstellung)
-> Validation (Validierung)
-> Completed (Abgeschlossen)
```

### Validierung

- Sinkt die Anzahl betroffener Geräte?
- Verschwindet die Recommendation (Empfehlung) oder reduziert sich der Scope?
- Sind verbleibende Geräte offline, ausgeschlossen oder technisch fehlerhaft?
- Entstehen neue Kompatibilitätsprobleme?
- Wurde das Fälligkeitsdatum eingehalten?
- Sind Ausnahmen sauber dokumentiert?

---

## 12. Exceptions und Risikoakzeptanz

Eine Exception (Ausnahme) ist sinnvoll, wenn ein Risiko nicht rechtzeitig oder nicht vollständig behoben werden kann.

Eine Ausnahme ist keine technische Fehlerbehebung. Sie dokumentiert eine bewusste und zeitlich begrenzte Risikoentscheidung.

### Mindestinhalte

- betroffene Empfehlung oder CVE,
- betroffene Software und Geräte,
- Business-Begründung,
- technisches Risiko,
- Risk Owner (Risikoverantwortlicher),
- App-Owner,
- Ablaufdatum,
- Review-Datum,
- kompensierende Maßnahmen,
- Exit-Plan.

### Kompensierende Maßnahmen

- Netzwerkzugriff reduzieren,
- lokale Administratorrechte entfernen,
- zusätzliche ASR-/Firewall-Kontrollen,
- Anwendung nur auf begrenzten Geräten zulassen,
- verstärktes Monitoring,
- Remote-Zugriff einschränken,
- Backup- und Recovery-Fähigkeit validieren.

**Merksatz:** Keine Ausnahme ohne Owner, Enddatum und überprüfbare Kompensationsmaßnahmen.

---

## 13. Threat Analytics

Threat Analytics (Bedrohungsanalyse) stellt kuratierte Microsoft Threat Intelligence mit Tenant-Kontext bereit.

Typischer Pfad:

```text
Threat intelligence (Bedrohungsinformationen)
-> Threat analytics (Bedrohungsanalyse)
```

Wichtige Bereiche:

| English term | Deutscher Begriff | Bedeutung |
|---|---|---|
| Latest threats | Neueste Bedrohungen | neue oder aktualisierte Berichte |
| High-impact threats | Bedrohungen mit hohen Auswirkungen | Berichte mit hoher Auswirkung auf die Organisation |
| Highest exposure threats | Bedrohungen mit der höchsten Exposition | Berichte, bei denen die eigene Umgebung besonders exponiert ist |
| Related incidents | Zugehörige Incidents | bereits vorhandene Security-Fälle |
| Impacted assets | Betroffene Ressourcen | Geräte, Benutzer oder andere Assets |
| Endpoint exposure | Endpunktexposition | anfällige oder nicht ausreichend geschützte Geräte |
| Recommended actions | Empfohlene Maßnahmen | Prävention, Mitigation oder Remediation |

### Betriebsnutzen

- aktuelle Kampagnen früh bewerten,
- prüfen, ob der Tenant bereits angegriffen wird,
- betroffene oder exponierte Geräte identifizieren,
- Schutzmaßnahmen und Security Recommendations ableiten,
- MSSP und Management gezielt informieren.

---

## 14. Reporting und Kennzahlen

Ein guter Betriebsbericht besteht nicht nur aus Zahlen. Er zeigt Status, Trend, Risiko, Owner und nächste Maßnahmen.

### Sinnvolle Berichtskategorien

| Kategorie | Beispielkennzahlen |
|---|---|
| Policy Health | Errors, Conflicts, Pending und nicht anwendbare Einstellungen |
| Update State | veraltete Security Intelligence, Engine oder Plattform |
| Exposure | Gefährdungsscore und Trend |
| Recommendations | offene, priorisierte und überfällige Empfehlungen |
| Vulnerabilities | kritische CVEs, Exploit verfügbar, betroffene Geräte |
| Remediation | offene Wartungsaktivitäten, Fristen und Fortschritt |
| Exceptions | Anzahl, Ablaufdaten und überfällige Reviews |
| Threat Analytics | aktuell relevante Kampagnen und Tenant-Exposition |

### Nicht empfehlenswert

- nur einen Gesamtscore berichten,
- Geräteanzahlen ohne Trend oder Kontext darstellen,
- abgeschlossene Maßnahmen nicht technisch validieren,
- überfällige Ausnahmen nicht hervorheben,
- keine Verantwortlichen oder Termine nennen.

---

## 15. Wiederkehrende Kontrollprozesse

### Wöchentlich

- Intune Endpoint Security Dashboard (Endpunktsicherheitsdashboard) prüfen,
- Fehler und Konflikte in relevanten Policies untersuchen,
- offene Intune Security Tasks (Sicherheitsaufgaben) kontrollieren,
- hoch priorisierte Security Recommendations prüfen,
- neue kritische CVEs und Softwareänderungen bewerten,
- Threat Analytics auf tenantrelevante Berichte prüfen,
- überfällige Remediation Activities und Exceptions eskalieren.

### Monatlich

- Trend von Exposure Score und Secure Score for Devices bewerten,
- Top Recommendations mit Client- und App-Ownern reviewen,
- Software End of Support (Ende des Supports) kontrollieren,
- Exceptions und Ablaufdaten prüfen,
- Reporting an IT-Leitung, Security und MSSP erstellen,
- Prozess- und Policy-Verbesserungen ableiten.

---

## Zusammenfassung

| Thema | Kernaussage |
|---|---|
| Betriebsmodell | Proaktiver Betrieb verhindert, dass bekannte Schwächen zu Incidents werden |
| Policy Health | Erfolgreiche Zuweisung, Konfliktfreiheit und lokale Wirksamkeit gemeinsam prüfen |
| Troubleshooting | Zielwert, Quellen, Assignment, lokalen Wert und Event Logs systematisch vergleichen |
| Exposure Management | Risiko aus Bedrohung, Ausnutzbarkeit, Asset-Wert und Business-Kontext priorisieren |
| Security Recommendations | Umsetzbare Maßnahmen mit klarem Owner und Scope |
| Software Inventory | Software, Versionen und betroffene Geräte tenantweit verstehen |
| CVE Investigation | Technische Schwere mit Exploit- und Tenant-Kontext verbinden |
| Remediation Request | Arbeitsauftrag zwischen Security und Intune-Team, keine automatische Änderung |
| Tracking | Deployment ist erst nach technischer Validierung abgeschlossen |
| Exception | Zeitlich begrenzte Risikoentscheidung mit Kompensationsmaßnahmen |
| Threat Analytics | Aktuelle Microsoft Threat Intelligence mit eigener Exposition verbinden |
| Reporting | Status, Trend, Risiko, Owner und Frist gemeinsam darstellen |

---

## Vokabelliste

| Begriff | Kurzbeschreibung |
|---|---|
| Policy Health | Zustand und Wirksamkeit zentraler Richtlinien |
| Assignment | Zuweisung einer Policy an Benutzer- oder Gerätegruppen |
| Device status | Gerätestatus einer Policy-Bereitstellung |
| Per-setting status | Status einzelner Einstellungen innerhalb einer Policy |
| Conflict | Widersprüchliche Konfiguration aus mehreren Quellen |
| Pending | Änderung oder Policy ist noch nicht final verarbeitet |
| Security baseline | Vordefinierte Sammlung empfohlener Sicherheitswerte |
| Settings catalog | Intune-Katalog mit granularen Konfigurationseinstellungen |
| Group Policy | Klassische Active-Directory-Gruppenrichtlinie |
| Tamper Protection | Schutz zentraler Defender-Einstellungen vor Manipulation |
| Security Intelligence | Defender-Erkennungs- und Signaturinformationen |
| Platform Update | Update der Defender-Produktplattform |
| Engine Update | Update der Scan- und Erkennungsengine |
| Exposure Management | Risikobasierte Verwaltung der organisatorischen Gefährdung |
| Exposure score | Gefährdungsscore der Organisation |
| Secure Score for Devices | Microsoft-Sicherheitsbewertung für Geräte |
| Vulnerability Management | Erkennung, Priorisierung und Behebung von Schwachstellen |
| Security Recommendation | Konkrete Sicherheitsempfehlung zur Risikoreduktion |
| CVE | Common Vulnerabilities and Exposures; eindeutige Schwachstellen-ID |
| CVSS | Technischer Schweregrad einer Schwachstelle |
| EPSS | Vorhersagewahrscheinlichkeit für die Ausnutzung einer CVE |
| Zero-day | Schwachstelle mit aktueller oder sehr neuer Ausnutzungslage |
| Software Inventory | Inventar erkannter Softwareprodukte und Versionen |
| Software Evidence | Nachweis, wo Software auf einem Gerät erkannt wurde |
| End of Support | Produkt erhält keine reguläre Herstellerunterstützung mehr |
| Exploit available | Öffentlicher Exploitcode ist verfügbar |
| Remediation | Behebung eines erkannten Sicherheitsrisikos |
| Remediation Request | Wartungsanforderung an das IT-/Intune-Team |
| Remediation Activity | Nachverfolgbarer Wartungsvorgang in Defender |
| Intune Security Task | Sicherheitsaufgabe in Intune aus Defender Vulnerability Management |
| Exception | Dokumentierte Ausnahme von einer Empfehlung |
| Risk Acceptance | Bewusste Akzeptanz eines verbleibenden Risikos |
| Compensating Control | Kompensierende Sicherheitsmaßnahme |
| Risk Owner | Verantwortliche Rolle für die Risikoentscheidung |
| Threat Intelligence | Informationen über Akteure, Kampagnen, Techniken und Indicators |
| Threat Analytics | Microsoft-Berichte mit Threat- und Tenant-Kontext |
| Impacted Assets | Von einer Bedrohung betroffene Ressourcen |
| Advanced Hunting | KQL-basierte Suche in Defender-XDR-Daten |
| DeviceTvmSoftwareInventory | Hunting-Tabelle für Softwarebestand |
| DeviceTvmSoftwareVulnerabilities | Hunting-Tabelle für Schwachstellen auf Geräten |
| DeviceTvmSoftwareVulnerabilitiesKB | Hunting-Wissensbasis zu CVEs |

---

## Microsoft-Referenzen

- https://learn.microsoft.com/defender-vulnerability-management/tvm-security-recommendation
- https://learn.microsoft.com/defender-vulnerability-management/tvm-software-inventory
- https://learn.microsoft.com/defender-vulnerability-management/tvm-remediation
- https://learn.microsoft.com/defender-xdr/threat-analytics
- https://learn.microsoft.com/intune/device-configuration/endpoint-security/manage-policies
- https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table
- https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilitieskb-table
