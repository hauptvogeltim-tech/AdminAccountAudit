# AdminAccountAudit – Architekturentwurf (zur Abnahme)

Status: **Entwurf v0.1** – noch kein Code. Offene Punkte sind mit **[OFFEN]**
markiert und hängen an den Rückfragen.

---

## 1. Grundsatzentscheidungen (Vorschlag)

| Thema | Vorschlag | Begründung |
|---|---|---|
| PowerShell (Audit-Arbeitsplatz) | **Windows PowerShell 5.1**, PS 7 wird geduldet, aber nicht garantiert | `ActiveDirectory` und vor allem `GroupPolicy` laufen unter PS 7 nur über die WinPS-Compat-Session (implicit remoting → deserialisierte Objekte, `Get-GPOReport` funktioniert, aber langsam/fragil). WPF unter 5.1 ist erprobt. |
| PowerShell (Zielhosts) | Remote-Skriptblöcke **PS-2.0-kompatibel** geschrieben, Fähigkeiten werden pro Host erkannt | Bei einer 20 Jahre alten Domäne sind 2008/2008 R2 wahrscheinlich. `Get-ScheduledTask` gibt es erst ab 2012 → dort greift automatisch die XML/schtasks-Methode. **[OFFEN: ältestes OS]** |
| GUI | **WPF** (XAML-Dateien getrennt vom Code-Behind) | Gewünscht; saubere Trennung, `DataGrid` + `ICollectionView` liefern Filter/Sortierung/Spaltenwahl nahezu geschenkt. Das bestehende UniFi-Tool im Repo nutzt WinForms – das Audit-Tool ist davon unabhängig. |
| SMTP | **`System.Net.Mail.SmtpClient`** hinter einer kleinen Transport-Abstraktion | In .NET Framework enthalten, keine DLLs zu verteilen/freizugeben. Microsoft rät für *neue* Entwicklung davon ab, weil moderne Protokolle fehlen (kein implizites TLS auf 465, kein OAuth). Für einen internen Relay mit STARTTLS/587 oder 25 reicht es. Die Abstraktion erlaubt später einen MailKit-Transport, falls DLLs erlaubt sind. **[OFFEN]** |
| Remote-Transport | **WinRM/PSRemoting primär**; optionaler, pro Methode deklarierter **RPC/DCOM-Fallback** (`Get-WinEvent -ComputerName`, CIM-über-DCOM, Remote-Registry) | Der Fallback ist gleichzeitig eine *unabhängige* Zweitquelle. Ob er erlaubt ist, steht in der Konfiguration. **[OFFEN]** |
| Konto-Identifikation | **SID-basiert** (Domänen-SID + RID 500), Namen nur als Zusatz | Das Konto kann umbenannt sein, und auf jedem Memberserver gibt es ein *lokales* „Administrator“ (ebenfalls RID 500, aber ein anderes Konto). Namensvergleich allein führt zu falschen Treffern. |
| Persistenz der Ergebnisse | Jeder Lauf schreibt eine **Ergebnisdatei (JSON)**; die GUI kann mehrere Läufe zusammenführen | Security-Logs auf DCs rollen oft nach Stunden bis wenigen Tagen über. Ein belastbares Bild entsteht erst durch wiederholte Läufe über Wochen. |

---

## 2. Projektstruktur

```
AdminAccountAudit/
├─ Start-AdminAudit.cmd              # Launcher: powershell.exe 5.1, -STA, -NoProfile
├─ AdminAudit.ps1                    # Einstieg: Config laden → Login → Hauptfenster
├─ AdminAudit.psd1 / .psm1           # Kernmodul (lädt Core/*, Collectors/*, Reporting/*)
│
├─ Config/
│  ├─ AdminAudit.config.json         # Org-Konfiguration (Gruppe, Zielkonten, SMTP, Scope, Timeouts)
│  └─ AdminAudit.config.schema.md    # Beschreibung aller Schlüssel
│
├─ Core/
│  ├─ Finding.ps1                    # New-AuditFinding / New-AuditCoverage / Test-AuditFinding (Schema)
│  ├─ TargetAccount.ps1              # Auflösung Zielkonto(en): SID, sAMAccountName, UPN, NetBIOS-Varianten,
│  │                                 #   Test-IsTargetAccount (Domain vs. lokal, Match-Qualität)
│  ├─ CrossCheck.ps1                 # Compare-AuditObservations → Confirmed / OnlyPrimary / OnlySecondary / Conflict
│  ├─ Scope.ps1                      # Resolve-AuditScope: Einzelhost | Liste | OU | ganze Domäne | DCs
│  ├─ Runner.ps1                     # RunspacePool, Timeout pro Host, Dispatch Remote/Lokal, Fehlerkapselung
│  ├─ CollectorRegistry.ps1          # Lädt Collectors/*.Collector.ps1, prüft Manifest
│  ├─ AuditLog.ps1                   # Eigenes Audit-Log (wer hat wann was abgefragt), JSON-Lines
│  ├─ Auth.ps1                       # ValidateCredentials + rekursive Gruppenprüfung
│  ├─ UserSettings.ps1               # %APPDATA%\AdminAccountAudit\<SID>.json
│  └─ ResultStore.ps1                # Lauf-Ergebnisse speichern/laden/zusammenführen
│
├─ Collectors/
│  ├─ _Template.Collector.ps1        # Vorlage für neue Kollektoren
│  ├─ Logon.Collector.ps1            # (Referenz) Security-Log Zielhosts + DCs, Cross-Check AD-Attribute
│  ├─ ScheduledTask.Collector.ps1
│  ├─ Service.Collector.ps1
│  ├─ Netlogon.Collector.ps1
│  ├─ Gpo.Collector.ps1
│  ├─ Autostart.Collector.ps1
│  └─ (später) IisAppPool, Dcom, StoredCredential, MappedDrive, SqlService …
│
├─ Gui/
│  ├─ LoginWindow.xaml
│  ├─ MainWindow.xaml
│  ├─ SettingsWindow.xaml
│  ├─ Themes/Light.xaml, Dark.xaml
│  └─ Gui.ps1                        # Code-Behind, Bindings, Filterlogik
│
├─ Reporting/
│  ├─ Export-AuditCsv.ps1
│  ├─ Export-AuditHtml.ps1           # HTML mit Diskrepanz-Block ganz oben
│  ├─ Templates/Report.html
│  └─ Send-AuditReport.ps1           # SmtpClient-Transport
│
├─ tests/                            # Pester 5 (nur Entwicklung) + Beispiel-Eventdaten
└─ docs/
   ├─ Design.md                      # dieses Dokument
   └─ Rechte-und-Voraussetzungen.md  # benötigte Rechte, Firewall, Verhalten bei Unerreichbarkeit
```

Laufzeitdaten (nicht im Repo):

```
%APPDATA%\AdminAccountAudit\settings\<UserSID>.json     # per-User-GUI-Einstellungen
%ProgramData%\AdminAccountAudit\runs\<RunId>.json       # Ergebnisse je Lauf  (Pfad konfigurierbar)
%ProgramData%\AdminAccountAudit\audit\audit-YYYYMM.jsonl# Audit-Log des Tools
```

---

## 3. Einheitliches Datenmodell

Es gibt **drei** Objektarten. Die geforderten acht Felder sind in allen
Fund-Objekten vorhanden und stehen immer zuerst.

### 3.1 `AuditFinding` – ein Fund

| Feld | Typ | Pflicht | Bedeutung |
|---|---|---|---|
| **Source** | string | ✔ | Kollektor, z. B. `Logon`, `ScheduledTask`, `Service`, `Gpo` |
| **Host** | string | ✔ | FQDN des Hosts, auf dem der Fund gemacht wurde (bei GPO: Domäne/DC) |
| **Account** | string | ✔ | Kontoangabe *wie gefunden* (z. B. `CORP\Administrator`, `.\Administrator`, `Administrator@corp.local`) |
| **ObjectType** | string | ✔ | `LogonEvent`, `ADLogonAttribute`, `ScheduledTask`, `Service`, `GpoSetting`, `AutostartEntry`, `NetlogonEntry`, … |
| **Detail** | string | ✔ | Einzeilige, menschenlesbare Beschreibung |
| **Timestamp** | datetime (UTC) | ✔ | Zeitpunkt *des Ereignisses* (Event-Zeit, Task-Letzter-Lauf, …); `$null`, wenn es keinen gibt (z. B. Dienstkonfiguration) |
| **Method** | string | ✔ | Konkrete Methode, z. B. `WinEvent/WinRM`, `WinEvent/RPC`, `CIM/Win32_Service`, `Registry/ObjectName`, `TaskXml`, `schtasks.exe` |
| **Confidence** | enum | ✔ | `High` / `Medium` / `Low` – Definition siehe 3.4 |
| FindingId | guid | ✔ | Eindeutige ID |
| RunId | guid | ✔ | Zuordnung zum Sammellauf |
| CollectedAt | datetime (UTC) | ✔ | Zeitpunkt der Erhebung (≠ Timestamp) |
| CollectedBy | string | ✔ | Identität, unter der gesammelt wurde |
| CollectorVersion | string | ✔ | Version des Kollektors |
| AccountSid | string | – | Aufgelöste SID, falls bestimmbar |
| AccountScope | enum | ✔ | `Domain` / `Local` / `Unresolved` – trennt Domänen-Administrator vom lokalen RID-500 |
| AccountMatch | enum | ✔ | `Sid` / `Name` / `Ambiguous` – wie der Treffer zustande kam |
| CorrelationKey | string | ✔ | Schlüssel für den Abgleich (z. B. `srv01|\Microsoft\Backup\Nightly`) |
| CrossCheck | enum | ✔ | `Confirmed` / `OnlyPrimary` / `OnlySecondary` / `Conflict` / `NotChecked` / `SecondaryUnavailable` |
| CrossCheckNote | string | – | Worin sich die Quellen unterscheiden |
| Attributes | hashtable | ✔ | Strukturierte, quellenspezifische Felder (filterbar), z. B. `LogonType`, `LogonTypeName`, `SourceIp`, `WorkstationName`, `EventId`, `TaskPath`, `ServiceName`, `StartMode`, `GpoGuid` |
| Evidence | object[] | ✔ | Rohbeobachtungen *aller* beteiligten Methoden inkl. Methode/Zeit – nichts wird stillschweigend aufgelöst |

Ein Beispiel (Logon, beide Quellen):

```powershell
[pscustomobject]@{
    Source           = 'Logon'
    Host             = 'dc01.corp.local'
    Account          = 'CORP\Administrator'
    ObjectType       = 'LogonEvent'
    Detail           = 'Logon Type 10 (RDP) von 10.1.2.33 / WS-IT-04'
    Timestamp        = [datetime]'2026-10-14T06:12:09Z'
    Method           = 'WinEvent/WinRM'
    Confidence       = 'High'
    FindingId        = '…'
    RunId            = '…'
    CollectedAt      = [datetime]'2026-10-15T08:00:31Z'
    CollectedBy      = 'CORP\svc-adminaudit'
    CollectorVersion = '1.0.0'
    AccountSid       = 'S-1-5-21-…-500'
    AccountScope     = 'Domain'
    AccountMatch     = 'Sid'
    CorrelationKey   = 'dc01.corp.local|Logon'
    CrossCheck       = 'Confirmed'
    CrossCheckNote   = 'lastLogon(dc01)=2026-10-14T06:12:09Z deckt sich mit jüngstem 4624'
    Attributes       = @{ EventId = 4624; LogonType = 10; LogonTypeName = 'RemoteInteractive'
                          SourceIp = '10.1.2.33'; WorkstationName = 'WS-IT-04'; LogonId = '0x3e7a1' }
    Evidence         = @( … )
}
```

### 3.2 `AuditCoverage` – was wurde *tatsächlich* geprüft

Pro **Host × Kollektor × Methode** genau ein Coverage-Datensatz, auch wenn
nichts gefunden wurde. Erst er macht „0 Treffer“ von „nicht prüfbar“
unterscheidbar (Prinzip *degradiert sauber*).

| Feld | Bedeutung |
|---|---|
| RunId, Source, Host, Method, CollectedAt, CollectedBy | Provenienz |
| Status | `Ok` / `Unreachable` / `AccessDenied` / `Timeout` / `NotSupported` / `Error` / `Skipped` |
| ResultCount | Anzahl Rohbeobachtungen (0 ist bei `Ok` eine gültige Aussage) |
| WindowStart / WindowEnd | Abgedeckter Zeitraum (z. B. ältestes Event im Security-Log) – bei Eventlog-Quellen Pflicht |
| Preconditions | z. B. Audit-Policy „Logon“ Erfolg/Fehler aktiv? Log zuletzt geleert (Event 1102)? Logon-Count-Replikation? |
| Message | Fehlermeldung / Hinweis |

Beispiel: `Security-Log auf srv07 ok, 0 Treffer, Zeitraum 13.10. 22:10 – 15.10. 08:00, Audit-Policy Logon=Success` →
Aussage „in diesen 34 h keine Anmeldung“, nicht „nie angemeldet“.

### 3.3 `AuditRun` – ein Sammellauf

`RunId, StartedAt, EndedAt, StartedBy, ToolVersion, ScopeDefinition, ResolvedHosts,
TargetAccounts (SID/Namen), CollectorsEnabled, Config-Hash, Findings[], Coverage[]`

### 3.4 Confidence – feste Definition

| Wert | Bedingung |
|---|---|
| **High** | Treffer per SID **und** Cross-Check `Confirmed` – oder eine autoritative Quelle mit SID-Treffer, deren Gegenprobe prinzipbedingt nicht existiert |
| **Medium** | Eine Methode, eindeutiger Treffer (SID oder eindeutig auflösbarer Name), Gegenprobe `NotChecked`/`SecondaryUnavailable` |
| **Low** | Nur Namens-Treffer ohne SID (z. B. Textfund in Netlogon-Log oder Skript in SYSVOL), `Ambiguous`, oder Cross-Check `Conflict` |

Ein `Conflict` erhöht nie die Confidence, sondern landet zusätzlich im
Diskrepanz-Block des Reports.

---

## 4. Kollektor-Vertrag

Ein Kollektor = eine Datei `Collectors/<Name>.Collector.ps1`, die ein
Manifest zurückgibt. Der Kern kümmert sich um Remoting, Timeouts, Fehler,
Provenienz und Cross-Check; der Kollektor liefert nur Rohdaten und
Zuordnungsregeln.

```powershell
@{
    Name        = 'ScheduledTask'
    Version     = '1.0.0'
    Scope       = 'Host'          # Host | DomainController | Domain (einmal pro Domäne, lokal)
    ObjectType  = 'ScheduledTask'
    Methods     = @(
        @{ Name = 'ScheduledTasks/CIM'; Role = 'Primary';   Transport = 'WinRM'
           MinOS = '6.2'; RemoteScript = { param($Target) … } }   # liefert Rohobjekte
        @{ Name = 'TaskXml';            Role = 'CrossCheck'; Transport = 'WinRM'
           RemoteScript = { param($Target) … } }
        @{ Name = 'schtasks.exe';       Role = 'CrossCheck'; Transport = 'WinRM'
           RemoteScript = { param($Target) … } }
    )
    CorrelationKey = { param($Obs) '{0}|{1}' -f $Obs.Host, $Obs.TaskPath }
    Compare        = { param($Primary, $Secondary) … }   # liefert Unterschiede je Feld
    ToFinding      = { param($Obs) … }                   # Rohobjekt → Detail/Attributes
}
```

Regeln:

- `RemoteScript` ist eigenständig (keine Abhängigkeit auf Modulfunktionen),
  PS-2.0-kompatibel und **ausschließlich lesend**.
- Das Zielkonto wird als `$Target` (SIDs + alle Namensvarianten)
  übergeben; Filterung möglichst schon remote (XPath-Filter bei Eventlogs),
  damit nicht ganze Logs übertragen werden.
- Jede Methode läuft in eigenem `try/catch` im Runner; ein Fehler erzeugt
  einen Coverage-Datensatz mit Status, nie einen Abbruch.
- Ein neuer Kollektor braucht keine Änderung an Kern, GUI oder Report.

---

## 5. Referenz-Kollektor `Logon` (Planung für Schritt 3)

| Teil | Methode | Inhalt |
|---|---|---|
| Primär, Zielhosts | `Get-WinEvent -FilterXml` über WinRM (Fallback RPC) | 4624, 4625, 4634, 4647, 4672 – XPath auf `TargetUserSid`/`SubjectUserSid` **und** `TargetUserName` (4625 hat oft keine SID) |
| Primär, DCs | wie oben | 4768, 4769, 4776 → welcher Client (IP/Workstation) wann gegen das Konto authentifiziert hat |
| Preconditions | `auditpol /get` (remote), Event 1102 (Log geleert), ältestes Event | Coverage-Zeitfenster, Hinweis bei deaktivierter Überwachung |
| Cross-Check | AD-Attribute: `lastLogon` **je DC** (Maximum), `lastLogonTimestamp`, `logonCount` je DC, `pwdLastSet`, `whenChanged`, `badPasswordTime` | Abgleich: jüngstes Event je DC vs. `lastLogon` dieses DCs; `lastLogonTimestamp` (bis 14 Tage Verzug) als grobe Plausibilisierung |

Bewusste Abweichungen, die *nicht* als Konflikt gelten (dokumentiert, nicht
verschluckt): `lastLogonTimestamp`-Replikationsverzug, Netzwerk-Logons, die
`lastLogon` nicht aktualisieren, Events außerhalb des Log-Zeitfensters.

---

## 6. Eigene Spuren des Tools

- Die Sammlung läuft **nicht** unter `Administrator`, sondern unter einem
  eigenen Audit-Konto (sonst verfälscht das Tool sein eigenes Ergebnis).
- Anmeldungen des Audit-Kontos werden in Findings nicht als Treffer gezählt,
  aber im Audit-Log festgehalten.

---

## 7. Offene Rückfragen

Siehe Gesprächsverlauf; Antworten fließen in v0.2 dieses Dokuments ein.
