# Session 2 - Übung 5
## Prozesskette bewerten

## Praxissituation

Im Defender Portal erscheint ein Alert mit einer Prozesskette wie:

```text
winword.exe -> powershell.exe -> rundll32.exe
```

Der betroffene Benutzer arbeitet in einer Fachabteilung und behauptet, nur ein normales Dokument geöffnet zu haben. Die IT muss entscheiden, ob es sich um eine legitime Automatisierung, ein False Positive oder einen möglichen Angriff handelt.


## Ziel der Übung

Die Teilnehmer sollen eine Prozesskette lesen, den Ursprung identifizieren, verdächtige Muster erkennen und eine erste Bewertung dokumentieren.

## Benötigte Berechtigungen

- Zugriff auf Microsoft Defender Portal
- Leserechte auf Alerts, Device Page und Timeline
- Optional Zugriff auf Advanced Hunting

## Grundprinzip

Eine Prozesskette beantwortet die Frage:

```text
Welcher Prozess hat welchen anderen Prozess gestartet?
```

Beispiele:

| Prozesskette | Erste Bewertung |
|---|---|
| `explorer.exe -> winword.exe` | Benutzer öffnet Word, meist normal |
| `winword.exe -> powershell.exe` | Verdächtig, häufig Angriffsmuster |
| `excel.exe -> cmd.exe -> script.bat` | Verdächtig, Kontext prüfen |
| `softwarecenter.exe -> powershell.exe` | Kann legitime Softwareverteilung sein |
| `psexec.exe -> cmd.exe` | Admin-Tool oder laterale Bewegung, Kontext kritisch |

## Aufgabe

Bewerte eine vorgegebene oder reale Prozesskette anhand folgender Fragen:

- Was ist der auslösende Prozess?
- Was ist der gestartete Prozess?
- Ist die Kombination im Unternehmenskontext normal?
- Gibt es auffällige Command-Line-Parameter?
- Gibt es Netzwerk- oder Dateiaktivitäten danach?
- Welche Entscheidung ist angemessen?

## Schritt-für-Schritt-Anleitung

### 1. Alert oder Device Timeline öffnen

1. Öffne das Microsoft Defender Portal.
2. Öffne den relevanten Alert oder das betroffene Gerät.
3. Wechsle zur Alert Story oder Device Timeline. (Filtere auf die letzten 30 Tage)
4. Suche die Prozessinformationen.

### 2. Parent- und Child-Prozess identifizieren

Dokumentiere:

| Feld | Beobachtung |
|---|---|
| Parent Process |  |
| Child Process |  |
| Benutzer |  |
| Gerät |  |
| Zeitpunkt |  |
| Prozesspfad |  |
| Command Line |  |

### 3. Prozesskette visualisieren

Trage die Kette ein:

```text
<Parent> -> <Child> -> <Folgeprozess>
```

Beispiel:

```text
winword.exe -> powershell.exe -> rundll32.exe
```

### 4. Verdächtigkeitsmerkmale prüfen

| Merkmal | Beobachtung | Bewertung |
|---|---|---|
| Office startet Shell oder Script Host |  |  |
| PowerShell mit `-EncodedCommand` |  |  |
| Start aus `%TEMP%`, `%APPDATA%` oder Download-Ordner |  |  |
| Unsigned oder seltene Datei |  |  |
| Externe Netzwerkverbindung nach Prozessstart |  |  |
| Unerwarteter Benutzerkontext |  |  |
| Prozess passt zu Softwareverteilung oder Admin-Tool |  |  |

### 5. Business-Kontext prüfen

Nicht jede auffällige Prozesskette ist automatisch bösartig. Prüfe:

| Frage | Antwort |
|---|---|
| Ist die Anwendung dem Fachbereich bekannt? |  |
| Gibt es legitime Makros oder Add-ins? |  |
| Ist der Benutzer ein Admin oder Standardbenutzer? |  |
| Ist das Gerät ein normales Clientgerät oder ein Spezialgerät? |  |
| Gibt es eine geplante Softwareverteilung oder Wartung? |  |

### 6. Entscheidung dokumentieren

| Entscheidung | Wann passend? |
|---|---|
| Legitim | Bekannte Anwendung, erwartetes Verhalten, App-Owner bestätigt |
| Verdächtig | Ungewöhnliche Kette, aber noch nicht eindeutig |
| (Sehr) Wahrscheinlich bösartig | Typisches Angriffsmuster, unbekannte Datei, auffällige Command Line |
| Weitere Prüfung nötig | Kontext fehlt oder widersprüchliche Hinweise |

## Optionale Advanced-Hunting-Abfragen (Können unter "Hunting" abgefragt werden)

Office-Prozesse, die Shells oder Skriptinterpreter starten:

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
```

PowerShell mit auffälligen Parametern:

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("EncodedCommand", "DownloadString", "Invoke-WebRequest", "IEX", "FromBase64String")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## Bewertung im Betriebsalltag

| Ergebnis | Nächste Aktion |
|---|---|
| Legitime Fachanwendung | Dokumentieren, ggf. ASR-Ausnahme prüfen |
| Verdächtige Kette ohne Schaden | MSSP/Security prüfen lassen, ggf. AV Scan |
| Verdächtige Kette mit Download/Ausführung | Incident eskalieren, Response Action prüfen |
| Eindeutig bösartig | Isolierung und Incident Response nach Freigabe prüfen |
| Unklar | Weitere Timeline-, File- und Netzwerkdaten prüfen |

## Diskussionsfragen

- Welche Prozessketten sind in unserem Unternehmen normal?
- Welche Admin-Tools können ähnliche Prozessketten erzeugen?
- Welche Kombinationen sollten immer kritisch sein?
- Welche Informationen fehlen oft für eine Bewertung?
- Wie dokumentieren wir den Business-Kontext?

## Merksatz

Eine Prozesskette ist der Kontext einer Aktivität. Erst der Zusammenhang aus Parent Process, Child Process, Command Line, Benutzer, Pfad und Zeitpunkt macht eine belastbare Bewertung möglich.


---
---

# POWERSHELL

---

### 1. Prozessbaum vereinfacht ausgeben

```powershell
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath |
    Sort-Object ParentProcessId, ProcessId |
    Format-Table -AutoSize
```

---

### 2. Bestimmte Prozesse mit Parent anzeigen

```powershell
$TargetProcessNames = @(
    "EXCEL.EXE",
    "WINWORD.EXE",
    "OUTLOOK.EXE",
    "msedgewebview2.exe",
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
)

$processes = Get-CimInstance Win32_Process

foreach ($p in $processes | Where-Object { $TargetProcessNames -contains $_.Name }) {
    $parent = $processes | Where-Object { $_.ProcessId -eq $p.ParentProcessId }

    [PSCustomObject]@{
        ProcessName = $p.Name
        ProcessId = $p.ProcessId
        ProcessPath = $p.ExecutablePath
        CommandLine = $p.CommandLine
        ParentProcessName = $parent.Name
        ParentProcessId = $parent.ProcessId
        ParentCommandLine = $parent.CommandLine
    }
} | Format-List
```

---

### 3. Datei-Signatur prüfen

```powershell
$FilePath = "C:\Windows\System32\svchost.exe"

Get-AuthenticodeSignature -FilePath $FilePath |
    Select-Object Status, StatusMessage, SignerCertificate |
    Format-List
```

---

### 4. Datei-Hash prüfen

```powershell
$FilePath = "C:\Windows\System32\svchost.exe"

Get-FileHash -Path $FilePath -Algorithm SHA256
```

---

### 5. Dateiversion und Hersteller prüfen

```powershell
$FilePath = "C:\Windows\System32\svchost.exe"

Get-Item $FilePath |
    Select-Object FullName, Length, CreationTime, LastWriteTime,
        @{Name="CompanyName";Expression={$_.VersionInfo.CompanyName}},
        @{Name="FileDescription";Expression={$_.VersionInfo.FileDescription}},
        @{Name="ProductName";Expression={$_.VersionInfo.ProductName}},
        @{Name="FileVersion";Expression={$_.VersionInfo.FileVersion}} |
    Format-List
```

---

### 6. Verdächtige Pfade prüfen

```powershell
Get-CimInstance Win32_Process |
    Where-Object {
        $_.ExecutablePath -match "\\Users\\|\\AppData\\|\\Temp\\|\\Downloads\\|\\ProgramData\\"
    } |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
    Format-List
```