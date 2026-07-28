# Session 5 – Übung 2
## Berechtigungsproblem zwischen Defender, PIM und Intune analysieren

## Praxissituation

Ein Mitarbeiter meldet:

```text
Ich kann den Incident im Defender Portal öffnen,
sehe aber beim betroffenen Gerät keine Response Actions.
Im Intune Admin Center kann ich die Antivirus-Policy lesen,
aber nicht bearbeiten.
```

Die Gruppe `RL_Defender_Operator` ist für den Mitarbeiter nur über PIM berechtigt. Es ist unklar, ob die PIM-Aktivierung fehlt, die Unified-RBAC-Permission nicht ausreicht, der Device Group Scope falsch ist oder ob für die Intune-Änderung eine separate Intune-Rolle erforderlich ist.

## Ziel

Die Teilnehmer grenzen das Problem systematisch auf eine der Ebenen PIM, Entra Group, Defender Unified RBAC, Device Group Scope oder Intune RBAC ein.

## Voraussetzungen

- Zugriff auf das eigene PIM-Portal beziehungsweise `My roles (Meine Rollen)`
- Lesender Zugriff auf Unified-RBAC-Rollen und Device Groups
- Lesender Zugriff auf Intune Tenant Administration und die eigenen Rollenzuweisungen
- Keine Rollen- oder Gruppenänderung in der Übung

## Schritt-für-Schritt-Anleitung

### 1. Symptom exakt einordnen

Unterscheide zunächst:

```text
A. Daten sind nicht sichtbar.
B. Daten sind sichtbar, aber eine Aktion fehlt.
C. Defender funktioniert, aber Intune-Policy kann nicht geändert werden.
```

Das geschilderte Beispiel enthält B und C. Deshalb müssen mindestens zwei Berechtigungsmodelle geprüft werden.

### 2. PIM-Aktivierung prüfen

Öffne:

```text
Microsoft Entra admin center
-> Identity governance (Identity Governance)
-> Privileged Identity Management
-> My roles (Meine Rollen)
```

Je nach Konfiguration kann die relevante Berechtigung unter erscheinen:

```text
Microsoft Entra roles (Microsoft-Entra-Rollen)
Groups (Gruppen)
```

Prüfe, ob die Mitgliedschaft in `RL_Defender_Operator` oder eine notwendige Entra-Rolle nur `Eligible (Berechtigt)` ist.


Nach erfolgreicher Aktivierung:

- einige Minuten warten,
- Defender Portal neu laden,
- bei Bedarf ab- und wieder anmelden oder ein privates Browserfenster verwenden.

### 3. Gruppenmitgliedschaft kontrollieren

Prüfe im Entra Admin Center lesend:

```text
Identity (Identität)
-> Groups (Gruppen)
-> All groups (Alle Gruppen)
-> RL_Defender_Operator
-> Members (Mitglieder)
```

Kontrolliere, ob die aktivierte Mitgliedschaft wirksam erscheint und ob verschachtelte Gruppen verwendet werden. Verschachtelung und Token-Aktualisierung können zu Verzögerungen oder unerwartetem Verhalten führen.

### 4. Unified-RBAC-Permission prüfen

Navigiere zu:

```text
Microsoft Defender Portal
-> System
-> Permissions (Berechtigungen)
-> Microsoft Defender XDR
-> Roles (Rollen)
```

Öffne die Rolle, der `RL_Defender_Operator` zugewiesen ist.

Für Response Actions muss die Rolle abhängig von der gewünschten Aktion geeignete Manage-Berechtigungen enthalten, insbesondere:

```text
Security operations (Sicherheitsvorgänge)
-> Security data (Sicherheitsdaten)
-> Response – manage (Reaktion – Verwalten)
```

Für Live Response sind zusätzliche Basic- oder Advanced-Live-Response-Permissions erforderlich.

Wenn nur Read-Permissions vorhanden sind, ist das Fehlen der Aktionen erwartbar.


### 5. Intune-Berechtigung separat prüfen

Öffne:

```text
Intune admin center
-> Tenant administration (Mandantenverwaltung)
-> Roles (Rollen)
-> My permissions (Meine Berechtigungen)
```

beziehungsweise die im Tenant verfügbare Ansicht der Role Assignments (Rollenzuweisungen).

Prüfe, ob der Mitarbeiter eine Rolle wie:

```text
Endpoint Security Manager
```

oder eine geeignete Custom Intune Role besitzt.

Beachte:

> Defender Unified RBAC berechtigt nicht zum Bearbeiten einer Intune-Antivirus- oder ASR-Policy.

Wenn nur Read Only Operator oder eine lesende Custom Role vorhanden ist, ist das Verhalten korrekt.

