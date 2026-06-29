# Session 2 - Übung 7
## False Positive und ASR-Ausnahme bewerten

## Praxissituation

Nach der Umstellung auf ASR Audit oder Block meldet ein Fachbereich, dass eine Anwendung oder ein Makro nicht mehr wie gewohnt funktioniert. Im Defender Portal ist ein ASR-Ereignis sichtbar. Der Fachbereich fordert eine schnelle Ausnahme für den kompletten Programmordner.

Diese Situation ist im Betrieb nach einer MDE-Migration sehr realistisch. Die Herausforderung besteht darin, legitime Geschäftsprozesse wiederherzustellen, ohne durch zu breite Ausnahmen die Schutzwirkung von ASR oder Defender Antivirus erheblich zu schwächen.

## Ziel der Übung

Die Teilnehmer sollen lernen, wie man einen möglichen False Positive bewertet, welche Informationen benötigt werden und wann eine ASR-Ausnahme vertretbar ist.

## Benötigte Berechtigungen

- Leserechte im Microsoft Defender Portal
- Leserechte auf ASR-Events und Device Timeline
- Für Änderungen: Berechtigung in Intune Endpoint Security
- Abstimmung mit App-Owner oder Fachbereich

## Wichtiger Hinweis

In dieser Übung sollen keine produktiven Ausnahmen ohne Freigabe erstellt werden. Ziel ist die Bewertung und Dokumentation einer möglichen Ausnahme.

## Aufgabe

Bewerte einen ASR-Treffer, der möglicherweise eine legitime Fachanwendung betrifft, und entscheide:

- Ist es wirklich ein False Positive?
- Ist eine Ausnahme notwendig?
- Kann die Ausnahme enger formuliert werden?
- Wer muss zustimmen?
- Wie wird die Ausnahme dokumentiert?

## Schritt-für-Schritt-Anleitung

### 1. ASR-Ereignis identifizieren

Öffne im Defender Portal den ASR-Report, den Alert oder die Device Timeline.

Dokumentiere:

| Feld | Beobachtung |
|---|---|
| Gerät |  |
| Benutzer |  |
| ASR-Regel |  |
| Modus | Audit / Warn / Block |
| Anwendung / Prozess |  |
| Pfad |  |
| Command Line |  |
| Zeitpunkt |  |

### 2. Fachlichen Kontext klären

| Frage | Antwort |
|---|---|
| Welche Anwendung ist betroffen? |  |
| Welcher Fachbereich nutzt sie? |  |
| Ist die Nutzung geschäftskritisch? |  |
| Gibt es einen App-Owner? |  |
| Ist das Verhalten dokumentiert oder erwartet? |  |
| Gibt es eine Alternative ohne Ausnahme? |  |

### 3. Technische Bewertung durchführen

Prüfe:

| Prüfpunk | Bewertung |
|---|---|
| Ist die Datei signiert? |  |
| Liegt die Datei in einem vertrauenswürdigen Installationspfad? |  |
| Wird die Datei aus `%TEMP%`, `%APPDATA%` oder Downloads gestartet? |  |
| Ist die Command Line plausibel? |  |
| Gibt es Netzwerkverbindungen zu unbekannten Zielen? |  |
| Gibt es ähnliche Treffer auf mehreren Geräten? |  |
| Gibt es weitere Alerts auf dem Gerät? |  |

### 4. Ausnahmebedarf bewerten

| Option | Wann geeignet? |
|---|---|
| Keine Ausnahme | Verhalten ist verdächtig oder unnötig |
| Anwendung anpassen | Hersteller/App-Team kann Verhalten ändern |
| Regel im Audit belassen | Noch keine ausreichende Entscheidungsgrundlage |
| Gezielte Ausnahme | Legitimer Prozess, eng definierter Pfad, dokumentierter Business Need |
| Breite Ausnahme | Nur als begründeter Sonderfall, möglichst vermeiden |

### 5. Risiko der Ausnahme bewerten

| Ausnahmeart | Risiko |
|---|---|
| Einzelne signierte EXE | Vergleichsweise eng |
| Konkreter Anwendungspfad | Mittel, abhängig von Schreibrechten |
| Benutzerbeschreibbarer Pfad | Hoch |
| Komplettes Laufwerk | Sehr hoch, nicht empfehlenswert |
| `C:\Windows` oder `C:\Users` breit | Sehr hoch, vermeiden |

### 6. Dokumentationsvorlage ausfüllen

| Feld | Eintrag |
|---|---|
| Antragsteller |  |
| Fachbereich |  |
| App-Owner |  |
| Betroffene Anwendung |  |
| ASR-Regel |  |
| Technische Ursache |  |
| Gewünschte Ausnahme |  |
| Engere Alternative möglich? |  |
| Risiko |  |
| Entscheidung |  |
| Genehmigung durch |  |
| Ablaufdatum / Review-Datum |  |
| Ticketnummer |  |

## Optionale Advanced-Hunting-Abfrage

ASR-Ereignisse für eine bestimmte Anwendung suchen:

```kql
let AppName = "example.exe";
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Asr"
| where InitiatingProcessFileName =~ AppName or FileName =~ AppName
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, AccountName
| order by Timestamp desc
```

ASR-Ereignisse nach Geräten und Prozessen zusammenfassen:

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Asr"
| summarize EventCount=count() by ActionType, InitiatingProcessFileName, FileName, DeviceName
| order by EventCount desc
```

## Erwartetes Ergebnis

Die Teilnehmer sollen unterscheiden können:

| Ergebnis | Bedeutung |
|---|---|
| Kein False Positive | Verhalten bleibt blockiert oder wird eskaliert |
| Wahrscheinlicher False Positive | App-Owner und Security prüfen gemeinsam |
| Ausnahme erforderlich | Ausnahme wird eng, dokumentiert und genehmigt umgesetzt |
| Regel noch nicht blockreif | Audit verlängern und weitere Daten sammeln |

## Bewertung im Betriebsalltag

| Beobachtung | Nächste Aktion |
|---|---|
| Legitimes signiertes Tool in geschütztem Pfad | Gezielte Ausnahme prüfen |
| Tool liegt in User-Temp | Keine schnelle Ausnahme, Risiko hoch |
| Viele Nutzer betroffen | Business Impact hoch, priorisierte Bewertung nötig |
| Nur ein Gerät betroffen | Lokale Besonderheit prüfen |
| Unklare Command Line | Security/MSSP einbinden |

## Diskussionsfragen

- Warum sind breite Ausnahmen gefährlich?
- Wer darf eine Ausnahme genehmigen?
- Wie lange soll eine Ausnahme gültig sein?
- Wie wird eine Ausnahme regelmäßig überprüft?
- Welche Informationen braucht Security, bevor eine Ausnahme akzeptiert wird?

## Merksatz

Eine Ausnahme ist keine Fehlerbehebung, sondern eine bewusste Risikoentscheidung. Sie muss eng, begründet, genehmigt und regelmäßig überprüft werden.


---
---

# POWERSHELL

---

### 1. Datei-Signatur prüfen

```powershell
$FilePath = "C:\Path\To\Application.exe"

Get-AuthenticodeSignature -FilePath $FilePath |
    Select-Object Status, StatusMessage, SignerCertificate |
    Format-List
```

---

### 2. SHA256-Hash der Datei berechnen

```powershell
$FilePath = "C:\Path\To\Application.exe"

Get-FileHash -Path $FilePath -Algorithm SHA256
```

---

### 3. Dateieigenschaften anzeigen

```powershell
$FilePath = "C:\Path\To\Application.exe"

Get-Item $FilePath |
    Select-Object FullName, Length, CreationTime, LastWriteTime,
        @{Name="CompanyName";Expression={$_.VersionInfo.CompanyName}},
        @{Name="FileDescription";Expression={$_.VersionInfo.FileDescription}},
        @{Name="ProductName";Expression={$_.VersionInfo.ProductName}},
        @{Name="FileVersion";Expression={$_.VersionInfo.FileVersion}} |
    Format-List
```

---

### 4. Aktuelle Defender-Ausschlüsse anzeigen

```powershell
Get-MpPreference | Select-Object `
    ExclusionPath,
    ExclusionProcess,
    ExclusionExtension,
    AttackSurfaceReductionOnlyExclusions |
    Format-List
```

---

### 5. ASR-only Exclusions anzeigen

```powershell
(Get-MpPreference).AttackSurfaceReductionOnlyExclusions
```

---

### 6. Beispiel: ASR-only Exclusion lokal hinzufügen

> Nur für Test/Lab verwenden. Produktive Ausnahmen müssen über Intune geplant, begründet und dokumentiert werden.

```powershell
$ExclusionPath = "C:\Path\To\Application.exe"

Add-MpPreference -AttackSurfaceReductionOnlyExclusions $ExclusionPath
```

---

### 7. Beispiel: ASR-only Exclusion lokal entfernen

> Nur für Test/Lab verwenden.

```powershell
$ExclusionPath = "C:\Path\To\Application.exe"

Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExclusionPath
```S