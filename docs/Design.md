# AdminAccountAudit – Architektur

Status: **v0.2** – Antworten auf die Rückfragen eingearbeitet, Kern und
Referenz-Kollektor `Logon` implementiert. GUI und Reporting folgen.

---

## 1. Festgelegte Rahmenbedingungen

| Thema | Entscheidung |
|---|---|
| Zielkonto | Nur der Domänen-Administrator `<NETBIOS>\Administrator`, identifiziert über **Domänen-SID + RID 500** (umbenennungsfest). Lokale RID-500-Konten der Server sind ein anderes Konto und werden standardmäßig nicht gemeldet (`IncludeLocalAdministrator`). |
| Umgebung | Eine Domäne, < 30 Server, 2 DCs. Server 2008 ist vorhanden → Remote-Code ist **PowerShell-2.0-kompatibel**. |
| PowerShell (Audit-Arbeitsplatz) | **Windows PowerShell 5.1**. PS 7 wird geduldet, aber nicht garantiert. |
| Kein RSAT nötig | AD-Zugriffe über ADSI/`DirectorySearcher`, nicht über das ActiveDirectory-Modul (GroupPolicy-Modul erst im GPO-Kollektor). |
| Remote-Transport | **WinRM zuerst, RPC/DCOM als Fallback** – je Methode deklariert und protokolliert, welcher Transport tatsächlich griff. |
| Identität | Gesammelt wird mit der Identität, unter der das Skript gestartet wurde (Kerberos, keine Passwörter im Speicher). Das Konto braucht die nötigen Rechte (siehe `Rechte-und-Voraussetzungen.md`). Läuft das Tool unter dem Zielkonto selbst, warnt es (die eigenen Anmeldungen würden das Ergebnis verfälschen). |
| Autorisierung (GUI) | Eine Rolle für alle: Mitgliedschaft in einer konfigurierbaren AD-Gruppe. Einstellungen werden pro Benutzer-SID gespeichert. |
| Mail | `System.Net.Mail.SmtpClient`, anonymer interner Relay, keine externen DLLs (kein MailKit). |
| Sprache | Oberfläche, Report und Fundtexte umschaltbar **de-DE / en-US**. Code-Bezeichner Englisch. |
| Zusätzliche Quellen | CrowdStrike Falcon / Identity Protection: Exporte werden später als eigener Import-Kollektor eingelesen (Format klären, sobald ein Beispielexport vorliegt). |

---

## 2. Projektstruktur (Ist-Stand)

```
AdminAccountAudit/
├─ Invoke-AdminAudit.ps1          # Kommandozeilen-Einstieg (bis die GUI steht)
├─ AdminAudit.psd1 / .psm1        # Kernmodul
├─ Config/AdminAudit.config.json  # Org-Konfiguration (überlagert eingebaute Defaults)
├─ Localization/de-DE.json, en-US.json
├─ Core/
│  ├─ Common.ps1                  # Zeit-/Pfad-/Objekt-Hilfen
│  ├─ Localization.ps1            # Get-AuditString, Sprachwechsel
│  ├─ Config.ps1                  # Defaults + JSON-Überlagerung
│  ├─ Finding.ps1                 # Finding / Coverage / Evidence / Confidence-Regeln
│  ├─ TargetAccount.ps1           # Zielkonto per SID, Zuordnung von Fundstellen
│  ├─ Scope.ps1                   # Single | List | OU | AllComputers | AllServers (+ DCs)
│  ├─ CrossCheck.ps1              # Timeline-, Zeitpunkt- und Schlüsselabgleich
│  ├─ RemoteHelpers.ps1           # PS-2.0-Hilfen, die mit jedem Remote-Skript mitlaufen
│  ├─ Runner.ps1                  # RunspacePool, Transport-Fallback, Timeout pro Host
│  ├─ AuditLog.ps1                # Audit-Log des Tools (JSON Lines)
│  ├─ ResultStore.ps1             # Läufe speichern / laden / zusammenführen
│  └─ Run.ps1                     # Invoke-AdminAuditRun: ein kompletter Lauf
├─ Collectors/
│  ├─ _Template.Collector.ps1
│  └─ Logon.Collector.ps1         # Referenzmuster
├─ tests/Test-AdminAudit.ps1      # ohne Pester, läuft auch unter Linux-pwsh
└─ docs/
```

Geplant: `Gui/` (WPF/XAML), `Reporting/` (HTML/CSV/SMTP), weitere Kollektoren.

Laufzeitdaten (konfigurierbar):

```
%ProgramData%\AdminAccountAudit\runs\run-<Zeit>-<RunId>.json   # Ergebnisse je Lauf
%ProgramData%\AdminAccountAudit\audit\audit-YYYYMM.jsonl      # Audit-Log des Tools
%APPDATA%\AdminAccountAudit\settings\<UserSID>.json           # GUI-Einstellungen je Benutzer
```

---

## 3. Datenmodell

### 3.1 `AuditFinding`

Die acht geforderten Felder stehen immer zuerst (wird getestet).

| Feld | Bedeutung |
|---|---|
| **Source** | Kollektor (`Logon`, …) |
| **Host** | FQDN, auf dem gefunden wurde (bei domänenweiten Attributen: DNS-Name der Domäne) |
| **Account** | Kontoangabe *wie gefunden* (`CORP\Administrator`, `administrator@CORP.LOCAL`, …) |
| **ObjectType** | `LogonEvent`, `DcAuthEvent`, `AccountEvent`, `SessionEvent`, `UserProfile`, `ADAttribute`, `ADAccount` (weitere Kollektoren ergänzen eigene) |
| **Detail** | Menschenlesbarer Text in der aktuellen Sprache |
| **Timestamp** | Zeitpunkt des Ereignisses (UTC); bei aggregierten Funden das jüngste |
| **Method** | Methode + tatsächlich genutzter Transport, z. B. `SecurityLog (WinRM)`, `ProfileList (Rpc)` |
| **Confidence** | `High` / `Medium` / `Low` (Regeln in 3.4) |
| FindingId, RunId, CollectedAt, CollectedBy, CollectorVersion | Provenienz |
| AccountSid, AccountScope (`Domain`/`Local`/`Unresolved`), AccountMatch (`Sid`/`Name`/`Ambiguous`) | Wie sicher der Bezug zum Zielkonto ist |
| CorrelationKey | Schlüssel für Abgleich und für das Zusammenführen mehrerer Läufe |
| CrossCheck, CrossCheckNote | Ergebnis der Gegenprobe (3.3) |
| DetailKey, DetailArgs | Sprachneutrale Form von Detail → Neu-Rendern bei Sprachwechsel |
| Attributes | Strukturierte, filterbare Felder: `EventId`, `LogonType`, `SourceIp`, `Workstation`, `Count`, `FirstSeen`, `LastSeen`, `RecordIds`, `Privileged`, … |
| Evidence | Rohbelege aller beteiligten Methoden (Methode, Rolle, Host, Transport, Rohdatensatz). Bei aggregierten Funden die ersten und letzten N Einzelereignisse, `RecordIds` vollständig. |

**Aggregation:** Gleichartige Ereignisse (gleicher Host, EventID, Logon-Type,
Quell-IP, Workstation, Status, Dienst …) werden zu einem Fund mit `Count`,
`FirstSeen` und `LastSeen` zusammengefasst. Das ergibt die Abhängigkeitslandkarte
(„von wo wird das Konto wie benutzt“), ohne die Einzelereignisse zu verlieren.

### 3.2 `AuditCoverage`

Ein Datensatz pro **Host × Kollektor × Methode**, auch bei 0 Treffern. Der Kern
erzeugt ihn automatisch aus jedem Methodenergebnis. Ein Kollektor kann das
also nicht vergessen.

`Status` (`Ok`/`Unreachable`/`AccessDenied`/`Timeout`/`NotSupported`/`Error`/`Skipped`),
`Transport`, `ResultCount`, `WindowStart`/`WindowEnd` (abgedeckter Zeitraum),
`Truncated`, `Preconditions` (Log-Größe/Modus, zuletzt geleert, effektive
Audit-Policy, WinRM-Zustand, Remote-PS-Version), `Message` (inkl. Fallback-Gründe).

### 3.3 Cross-Check-Zustände

| Zustand | Bedeutung | Im Report als Diskrepanz |
|---|---|---|
| `Confirmed` | Beide Quellen sehen dasselbe | |
| `Partial` | Aggregat: nur ein Teil der Einzelereignisse bestätigt | ✔ |
| `OnlyPrimary` | Gegenprobe lief und deckt den Zeitraum ab, sieht es aber nicht | ✔ |
| `OnlySecondary` | Nur die Gegenprobe sieht es | ✔ |
| `Conflict` | Quellen widersprechen sich inhaltlich | ✔ |
| `NotChecked` | Es gibt keine unabhängige Zweitquelle, oder der Zeitpunkt liegt außerhalb ihres Zeitfensters | |
| `Unverifiable` | Eine Zweitquelle gibt es, sie war aber nicht verfügbar (Fehler/unerreichbar) | |

### 3.4 Confidence

| Wert | Bedingung |
|---|---|
| **High** | SID-Treffer und `Confirmed` – oder autoritative Einzelquelle per SID (z. B. Kontoattribute aus dem AD) |
| **Medium** | Eindeutiger Treffer (SID oder Name mit passender Domäne), Gegenprobe nicht bestätigend |
| **Low** | `Ambiguous` (Name ohne Domänenkontext) oder `Conflict` |

---

## 4. Kollektor-Vertrag

Ein Kollektor ist eine Datei `Collectors\<Name>.Collector.ps1`, die ein Manifest
zurückgibt (Vorlage: `_Template.Collector.ps1`).

- `Methods[]`: `Name`, `Role` (`Primary`/`CrossCheck`), `Scope` (`Host`/`DomainController`),
  `Transports` (Reihenfolge = Fallback), `Script`.
- `Script` läuft auf dem Ziel (WinRM) oder lokal mit `$ComputerName` (Rpc/Ldap).
  Der Runner setzt `Core\RemoteHelpers.ps1` davor. Das Skript ist PS-2.0-kompatibel
  (wird statisch getestet), rein lesend und liefert genau ein `New-AuditRemoteResult`.
- `Analyze` läuft lokal mit allen Methodenergebnissen und erzeugt die Funde.
- Fehlerbehandlung, Timeouts, Coverage und Provenienz übernimmt der Kern.

**Kompatibilitätsmodus** (`Collection.CompatibilityMode`, CLI `-LegacyMode`, später GUI-Checkbox
„Abwärtskompatibilitätsmodus“): Methoden können `MinPSVersion` (gilt für die Ausführung auf dem
Ziel per WinRM) und `MinOSVersion` (Vergleich mit `operatingSystemVersion` aus dem AD) deklarieren.

| Modus | Verhalten |
|---|---|
| `Auto` (Standard) | Remote-PS-Version (aus der WinRM-Sitzung) und OS-Version je Host erkennen. Methoden mit höheren Anforderungen werden dort übersprungen, es greifen die Fallback-Methoden. Unbekannte Version → Methode läuft. |
| `Legacy` | Jeder Host wird wie Server 2008 / PowerShell 2.0 behandelt. Für den Fall, dass die Erkennung nicht vertrauenswürdig ist (z. B. veraltete OS-Angaben im AD). |

Eine übersprungene Methode erscheint in der Coverage als `Skipped` mit Begründung. Die von ihr
abhängigen Gegenproben werden `Unverifiable` und gelten nie als „nichts gefunden“.
Methoden ohne `MinPSVersion` müssen PS-2.0-kompatibel sein (statischer Test), sie laufen also überall.
Neuere PowerShell-Versionen werden auf den Zielen bewusst **nicht** installiert (Read-only-Prinzip;
PS 7 unterstützt Server 2008/2008 R2 ohnehin nicht).

**Transport-Fallback:** Der nächste Transport wird nur versucht, wenn der Fehler
am Transport lag (keine WinRM-Session, RPC nicht erreichbar). Ein „Zugriff
verweigert“ wird dagegen direkt als Status gemeldet und nicht über einen anderen
Weg verschleiert.

---

## 5. Referenz-Kollektor `Logon`

| Methode | Rolle | Ort | Inhalt |
|---|---|---|---|
| `SecurityLog` | Primär | jeder Host | 4624, 4625, 4634, 4647, 4648, 4672; auf DCs zusätzlich 4768, 4769, 4771, 4776, 4740, 4723, 4724, 4738. XPath-Filter auf SID bzw. Namensvarianten. Coverage: Log-Zeitfenster, Größe, Modus, zuletzt geleert (1102), effektive Audit-Policy (`auditpol /r`, nur über WinRM). |
| `TerminalServicesLog` | Gegenprobe | jeder Host | LocalSessionManager 21–25, RemoteConnectionManager 1149 |
| `WinlogonSystemLog` | Gegenprobe | jeder Host | System-Log Winlogon 7001/7002 (UserSid) |
| `ProfileList` | Gegenprobe | jeder Host | Registry-Profil des Kontos (inkl. `.bak`), Ladezeit, NTUSER.DAT-Zeitstempel. Reicht weiter zurück als jedes Eventlog. |
| `ADAttributes` | Gegenprobe | jeder DC (LDAP) | `lastLogon`, `logonCount`, `badPasswordTime`, `badPwdCount` (je DC), `lastLogonTimestamp`, `pwdLastSet` + Replikationsmetadaten, `userAccountControl`, SPNs |

Abgleiche:

| Aussage | Primär | Gegenprobe | Regel |
|---|---|---|---|
| Interaktive/RDP-Anmeldung (Typ 2/10/11, 7 bei Reconnect) | 4624 | LSM 21/25, RCM 1149, Winlogon 7001 | Zeitreihe, ±120 s, jede Quelle einzeln, Ergebnis zusammengeführt |
| Sitzung ohne 4624 | – | LSM/RCM/Winlogon | `OnlySecondary`, wenn das Security-Log den Zeitpunkt abdeckt |
| 4672 (Sonderrechte) | – | – | wird an die 4624 mit gleicher LogonId gehängt (`Privileged`) |
| Profil-Ladezeit | ProfileList | 4624 Typ 2/4/5/10/11 | ±300 s; Profil fehlt trotz interaktiver Anmeldungen → `Conflict` |
| `lastLogon` je DC | AD | 4768/4776 (Erfolg) auf diesem DC | Zeitpunkt-Abgleich ±300 s |
| `badPasswordTime` je DC | AD | 4771/4625/4776 (Fehler) auf diesem DC | Zeitpunkt-Abgleich |
| `pwdLastSet` | AD (alle DCs) | Gleichheit über DCs + 4723/4724 | unterschiedliche Werte → `Conflict` |
| `lastLogonTimestamp` | AD | Maximum aller `lastLogon` | muss innerhalb des Sync-Intervalls liegen |
| Netzwerk-, Dienst- und Batch-Logons | 4624 | – | keine unabhängige Zweitquelle auf dem Host → `NotChecked` (die Domänensicht liefern die DC-Ereignisse) |

Bekannte Grenzen (stehen auch in der Coverage):

- XPath vergleicht Werte case-sensitiv. Es werden die üblichen Schreibweisen
  abgefragt; exotische Mischschreibung bei Namens-Ereignissen (4625/4776/4769)
  kann durchrutschen. SID-basierte Ereignisse sind davon nicht betroffen.
- Per RPC lässt sich die Audit-Policy nicht lesen (`unknown (RPC transport)`).
- Ist `MaxEventsPerQuery` erreicht, wird `Truncated` gesetzt und das Zeitfenster
  auf das älteste gelieferte Ereignis verkürzt.

---

## 6. Nächste Schritte

1. Testlauf in der Domäne mit `Invoke-AdminAudit.ps1`, Rückmeldung zu
   Coverage-Lücken (WinRM/RPC, Rechte, Audit-Policy).
2. Kollektoren Geplante Aufgaben, Dienste, Netlogon, GPO, Autostart nach dem
   Muster von `Logon`.
3. GUI (WPF): Login + Gruppenprüfung, Grid mit Filtern, Einstellungen je Benutzer,
   Sprachumschaltung, Laden/Zusammenführen gespeicherter Läufe.
4. Reporting: HTML mit Diskrepanz-Block oben, CSV, SMTP-Versand.
5. Import-Kollektor für CrowdStrike-Exporte.
