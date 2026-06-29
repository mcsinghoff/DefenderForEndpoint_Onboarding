# Session 2 - Übung 1
## ASR-Policy in Intune finden und Modus prüfen

## Praxissituation

Nach der MDE-Migration soll eine Pilotgruppe erste Attack Surface Reduction Regeln erhalten. Der Fachbereich fragt, ob die Regeln (oder eine einzelne Regel) bereits produktiv blockieren oder nur im Audit Mode laufen. Gleichzeitig soll die IT sicherstellen, dass keine Regel versehentlich auf `Block` steht, bevor die Pilotdaten ausgewertet wurden.

Diese Situation kommt im Betriebsalltag häufig vor, weil ASR-Regeln sehr wirksam sind, aber bei falscher oder zu früher Blockierung legitime Geschäftsprozesse, Office-Automatisierungen, Admin-Skripte oder Softwareverteilung beeinträchtigen können.

## Ziel der Übung

Wir möchten eine ASR-Policy in Intune finden, die Zuweisung prüfen und erkennen, in welchem Modus einzelne ASR-Regeln konfiguriert sind.

## Benötigte Berechtigungen

- Leserechte im Intune Admin Center
- Idealerweise Rolle `Endpoint Security Manager` oder vergleichbare Leseberechtigung
- Zugriff auf die für den Pilot verwendeten Gerätegruppen

## Ausgangspunkt

Portal:

```text
https://intune.microsoft.com
```

Pfad:

```text
Endpoint security -> Attack surface reduction (Verringerung der Angriffsfläche)
```

Je nach Tenantversion kann die Navigation leicht anders benannt sein.

## Aufgabe

Finde die ASR-Policy für die Windows-11-Pilotgeräte und prüfe:

- Welche Regeln sind konfiguriert?
- Welche Regeln stehen auf `Audit`?
- Welche Regeln stehen auf `Warn` oder `Block`?
- Welche Gruppen erhalten die Policy?
- Gibt es ausgeschlossene Gruppen?
- Gibt es Geräte mit Fehlerstatus?

## Schritt-für-Schritt-Anleitung

### 1. ASR-Bereich öffnen

1. Öffne das Intune Admin Center.
2. Navigiere zu:

   ```text
   Endpoint security -> Attack surface reduction
   ```

3. Suche die ASR-Policy für Windows 11 oder die Pilotgruppe.

### 2. Policy-Grunddaten prüfen

Öffne die Policy und dokumentiere:

| Prüffeld | Beobachtung |
|---|---|
| Policy-Name |  |
| Plattform |  |
| Profiltyp |  |
| Erstellt am / geändert am |  |
| Letzte Änderung durch |  |

### 3. Konfigurierte ASR-Regeln prüfen

Prüfe die einzelnen ASR-Regeln und deren Modus.

| ASR-Regel | Modus | Kommentar |
|---|---|---|
| Office Child Processes blockieren |  |  |
| Credential Theft aus LSASS blockieren |  |  |
| Obfuskierten Skriptcode blockieren |  |  |
| Ausführbare Inhalte aus E-Mail/Webmail blockieren |  |  |
| Ransomware-Schutzregel |  |  |
| USB-bezogene Regel |  |  |
| Weitere Regeln |  |  |

### 4. Assignments prüfen

Prüfe unter `Assignments`:

| Prüffrage | Beobachtung |
|---|---|
| Welche Gruppen sind eingeschlossen? |  |
| Welche Gruppen sind ausgeschlossen? |  |
| Ist die Pilotgruppe korrekt enthalten? |  |
| Gibt es Überschneidungen mit Produktionsgruppen? |  |
| Gibt es separate Rollout-Wellen? |  |

### 5. Device Status prüfen

Prüfe den Policy-Status:

| Status | Bedeutung im Betrieb |
|---|---|
| Succeeded | Policy wurde erfolgreich angewendet |
| Error | Policy konnte nicht vollständig angewendet werden |
| Conflict | Eine andere Policy oder Baseline setzt widersprüchliche Werte |
| Pending | Gerät hat die Policy noch nicht final verarbeitet oder noch nicht eingecheckt |
| Not applicable | Policy passt nicht auf Gerät, Plattform oder Scope |

Dokumentiere beispielhaft ein Gerät mit erfolgreichem Status und ein Gerät mit Fehler/Pending, falls vorhanden.

| Gerät | Status | Letzter Check-in | Bemerkung |
|---|---|---|---|
|  |  |  |  |
|  |  |  |  |

## Erwartetes Ergebnis

Aus den Informationen können wir beantworten:

- Welche ASR-Policy ist für die Pilotgeräte relevant?
- Welche Regeln sind nur im Audit Mode?
- Gibt es versehentlich blockierende Regeln?
- Welche Geräte haben die Policy erhalten?
- Welche Geräte müssen wegen Fehlerstatus geprüft werden?

## Bewertung im Betriebsalltag

| Beobachtung | Mögliche Bewertung |
|---|---|
| Alle Regeln auf Audit | Geeignet für Pilotphase und Auswirkungsanalyse |
| Einzelne Regeln auf Block | Prüfen, ob bereits freigegeben und pilotiert |
| Unerwartete Produktionsgruppe zugewiesen | Risiko für unbeabsichtigte Blockierungen |
| Viele Geräte mit Pending | Intune Check-in oder Zuweisung prüfen |
| Konflikte | Andere Policies, Security Baselines oder GPOs prüfen |

## Diskussionsfragen

- Welche ASR-Regeln würden wir zuerst nur auditieren?
- Welche Regeln könnten später direkt auf Block gehen?
- Welche Fachbereiche oder Anwendungen müssen vor Block Mode eingebunden werden?
- Wie dokumentieren wir eine Änderung von Audit auf Block?
- Wer gibt eine produktive Blockierung frei?

---
---

# POWERSHELL:
Mit PowerShell prüfen, welche ASR-Regeln lokal auf dem Client konfiguriert sind.

---

### 1. Defender-Modul anzeigen

```powershell
Get-Command -Module Defender
```

---

### 2. ASR-Regeln und Aktionen lokal ausgeben

```powershell
$pref = Get-MpPreference

$asr = for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
    [PSCustomObject]@{
        RuleId = $pref.AttackSurfaceReductionRules_Ids[$i]
        Action = $pref.AttackSurfaceReductionRules_Actions[$i]
    }
}

$asr | Format-Table -AutoSize
```

### 3. ASR-Actions lesbarer machen

Typische Werte:

| Wert | Bedeutung |
|---:|---|
| `0` | Disabled |
| `1` | Block / Enabled |
| `2` | Audit |
| `6` | Warn |

```powershell
$pref = Get-MpPreference

for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {

    $actionValue = [int]$pref.AttackSurfaceReductionRules_Actions[$i]

    $actionText = switch ($actionValue) {
        0 { "Disabled" }
        1 { "Block / Enabled" }
        2 { "Audit" }
        6 { "Warn" }
        default { "Unknown / Other" }
    }

    [PSCustomObject]@{
        RuleId = $pref.AttackSurfaceReductionRules_Ids[$i]
        ActionValue = $actionValue
        Action = $actionText
    }
} | Format-Table -AutoSize
```

---

### 4. Häufige ASR-Regeln mit Namen zuordnen

```powershell
$AsrRuleNames = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block Office applications from creating child processes"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2b" = "Block credential stealing from LSASS"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes from USB"
}

$pref = Get-MpPreference

for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {

    $ruleId = $pref.AttackSurfaceReductionRules_Ids[$i].ToString().ToLower()
    $actionValue = [int]$pref.AttackSurfaceReductionRules_Actions[$i]

    $actionText = switch ($actionValue) {
        0 { "Disabled" }
        1 { "Block / Enabled" }
        2 { "Audit" }
        6 { "Warn" }
        default { "Unknown / Other" }
    }

    [PSCustomObject]@{
        RuleName = $AsrRuleNames[$ruleId]
        RuleId = $ruleId
        Action = $actionText
    }
} | Format-Table -AutoSize
```