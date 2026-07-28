# Session 5 – Übung 3
## Response Action im Defender Audit Log nachvollziehen

## Praxissituation

Ein freigegebenes Testgerät wurde während einer früheren Übung isoliert und später wieder aus der Isolation entlassen. Im Ticket wurde die ausführende Person nicht korrekt dokumentiert. Die interne IT muss nachvollziehen:

- wer die Isolation ausgelöst hat,
- wann die Aktion stattfand,
- ob sie erfolgreich war,
- wer das Gerät wieder freigegeben hat.

## Ziel

Die Teilnehmer suchen eine konkrete Defender-for-Endpoint-Aktivität im Microsoft-365-Audit-Log und gleichen sie mit Device Timeline (Gerätezeitachse), Action Center (Aktionscenter) und Ticketzeitraum ab.

## Voraussetzungen

- Rolle `View-Only Audit Logs` oder `Audit Logs` beziehungsweise eine gleichwertige Berechtigung
- Microsoft Purview Auditing ist im Tenant verfügbar
- Kenntnis von Testgerät, ungefährem Zeitraum und – falls möglich – ausführendem Konto
- Nur lesende Recherche

## Schritt-für-Schritt-Anleitung

### 1. Ausgangsdaten festlegen

Verwende einen bekannten Schulungsfall oder eine bereits abgeschlossene Response Action. Benötigt werden:

- Gerätename,
- ungefährer Tag und Zeitraum,
- Aktion wie Isolation oder Release from Isolation,
- optional vermuteter Benutzer.

Keine neue Isolation nur für diese Übung auslösen.

### 2. Audit öffnen

Öffne im Microsoft Defender Portal:

```text
System
-> Audit (Überwachung)
```

Falls der Eintrag dort nicht verfügbar ist, öffne Microsoft Purview und wähle:

```text
Solutions (Lösungen)
-> Audit (Überwachung)
```

### 3. Neue Suche konfigurieren

Setze einen engen Zeitraum um die bekannte Aktion. Filtere – je nach verfügbarer Portaloberfläche – nach:

- Activities (Aktivitäten),
- Users (Benutzern),
- Workloads,
- Record types (Datensatztypen).

Suche nach Defender-for-Endpoint- beziehungsweise Response-Action-Aktivitäten. Bei unbekannter exakter Aktivitätsbezeichnung beginne breiter mit Microsoft Defender for Endpoint und grenze danach ein.

### 4. Ergebnisse durchsuchen

Achte auf Einträge zu:

```text
Isolate device (Gerät isolieren)
Release device from isolation (Gerät aus Isolation freigeben)
```

Öffne den relevanten Audit Record (Überwachungsdatensatz).

Prüfe:

- Creation time (Erstellungszeit),
- User (Benutzer),
- Operation/Activity (Vorgang/Aktivität),
- Workload,
- Object/Target (Objekt/Ziel),
- Result status (Ergebnisstatus),
- zusätzliche Geräte- oder Action-IDs.

### 5. Mit Action Center vergleichen

Öffne im Defender Portal:

```text
Actions & submissions (Aktionen und Übermittlungen)
-> Action center (Aktionscenter)
-> History (Verlauf)
```

Suche nach dem Testgerät und dem betreffenden Zeitraum.

Vergleiche:

- Action Type (Aktionstyp),
- Submitted by (Übermittelt von),
- Status,
- Zeitpunkt,
- Quelle der Aktion,
- gegebenenfalls Comment (Kommentar).

### 6. Mit Device Timeline vergleichen

Öffne:

```text
Assets (Bestand)
-> Devices (Geräte)
-> freigegebenes Testgerät
-> Timeline (Zeitachse)
```

Grenze den Zeitraum ein und suche nach der Isolation beziehungsweise Freigabe. Die Timeline zeigt den Gerätebezug, während Audit und Action Center die administrative Nachvollziehbarkeit ergänzen.

### 7. Optional: Audit über PowerShell suchen

Voraussetzungen:

- Exchange Online PowerShell-Modul,
- passende Audit-Berechtigung,
- moderne Anmeldung.

```powershell
Connect-ExchangeOnline

$StartDate = (Get-Date).AddDays(-7)
$EndDate   = Get-Date

$Results = Search-UnifiedAuditLog `
    -StartDate $StartDate `
    -EndDate $EndDate `
    -ResultSize 5000

$Results |
    Where-Object {
        $_.Operations -match 'isolat' -or
        $_.AuditData  -match 'isolat'
    } |
    Select-Object CreationDate,UserIds,Operations,AuditData |
    Format-List
```

Die verfügbaren Felder und Operation-Namen können sich ändern. Die Portalrecherche bleibt deshalb der primäre Übungsweg.

