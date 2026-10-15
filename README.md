# AdminAccountAudit

Inventarisiert **read-only** alle Abhängigkeiten vom Domänen-Administratorkonto
(Domänen-SID + RID 500): wo, wie und von wo es benutzt wird. Damit lässt sich das
Konto später kontrolliert aus dem Betrieb herauslösen.

Grundsätze: Es wird nichts verändert. Jede Aussage hat nach Möglichkeit eine zweite,
unabhängige Quelle. Jeder Fund trägt seine Herkunft. Nicht erreichbare Quellen
werden als solche gemeldet und nie als „nichts gefunden“ gewertet.

**Stand:** Kern + Kollektor `Logon` (Security-Log, DC-Authentifizierung,
TerminalServices-/Winlogon-Logs, Benutzerprofile, AD-Attribute je DC),
Diagnose-Log mit einstellbarem Detailgrad. GUI, Reporting und die übrigen
Kollektoren folgen.

## Testlauf

Windows PowerShell 5.1, mit einem berechtigten Konto (nicht `Administrator`):

```powershell
# alle Server laut Config + DCs
.\Invoke-AdminAudit.ps1

# nur bestimmte Hosts (DCs werden ergänzt), Ergebnis zusätzlich als CSV, englisch
.\Invoke-AdminAudit.ps1 -ComputerName srv01,srv02 -CsvPath .\funde.csv -Language en-US

# Fehlersuche: alles ins Diagnose-Log, Verbose-Meldungen live auf der Konsole
.\Invoke-AdminAudit.ps1 -ComputerName srv01 -LogLevel Debug -Verbose
```

Mit `-LegacyMode` werden alle Hosts wie Server 2008 / PowerShell 2.0 behandelt
(Abwärtskompatibilitätsmodus). Standard ist die automatische Erkennung je Host.

Konfiguration: `Config\AdminAudit.config.json` (Scope, Timeouts, Parallelität,
Toleranzen, Logging, SMTP). Nicht angegebene Schlüssel nehmen die Defaults aus `Core\Config.ps1`.

## Ablage der Ergebnisse und Logs

| Was | Wo (Standard) | Zweck |
|---|---|---|
| Läufe | `%ProgramData%\AdminAccountAudit\runs\run-*.json` | Funde + Coverage je Lauf, später in der GUI lad- und zusammenführbar |
| Audit-Log | `%ProgramData%\AdminAccountAudit\audit\audit-YYYYMM.jsonl` | Wer hat wann was abgefragt – immer an |
| Diagnose-Log | `%ProgramData%\AdminAccountAudit\logs\diag-YYYYMMDD.log` | Was das Tool intern tut – Detailgrad einstellbar |

## Diagnose-Log

Detailgrad (aufsteigend): `Off` · `Error` · `Warning` · `Info` · `Verbose` · `Debug`.
Datei und Konsole haben je eine eigene Schwelle.

| Level | Inhalt (Beispiele) |
|---|---|
| `Error` | Analyse oder Host-Job unerwartet abgebrochen |
| `Warning` | Methode fehlgeschlagen (Zugriff verweigert, nicht erreichbar), Host-Timeout, DNS-Fehler, Security-Log geleert, Audit-Policy für relevante Kategorien aus, Ergebnis abgeschnitten |
| `Info` | Laufbeginn/-ende mit Kennzahlen, Zielkonto, Scope, WinRM nicht verfügbar → Fallback, übersprungene Methoden (Kompatibilitätsmodus) |
| `Verbose` | Jede Methode mit Transport, Dauer und Trefferzahl; WinRM-Sitzung und Remote-PS-Version; Log-Größe und -Zeitfenster je Host; Profil- und AD-Werte |
| `Debug` | Vollständige XPath-Abfragen, Audit-Policy je Kategorie, effektive Konfiguration, Stacktraces |

Einstellen:

- dauerhaft in der Konfiguration: `Logging.Level`, `Logging.ConsoleLevel`, `Format` (`Text`/`Json`),
  `MaxFileSizeMB` (danach `diag-<Tag>-1.log` …), `RetentionDays`
- pro Lauf: `-LogLevel <Level>` (Datei), `-ConsoleLogLevel <Level>`, oder kurz `-Verbose` / `-Debug`
- später in der GUI: Auswahlfeld in den Einstellungen

Meldungen, die auf den Zielhosts entstehen (z. B. „Audit-Policy aus“), werden mitgesammelt
und mit Host und Methode (`Remote:Logon/SecurityLog`) eingetragen. Werte mit Schlüsseln wie
`Password`, `Credential` oder `Token` werden immer als `***` geschrieben.

Anzeigen und filtern:

```powershell
.\Show-AdminAuditLog.ps1 -Level Warning -Last 50
.\Show-AdminAuditLog.ps1 -RunId 3f2a91c0 -HostName srv01 -Level Debug
.\Show-AdminAuditLog.ps1 -Follow -Level Verbose                 # live mitlesen, Strg+C beendet
.\Show-AdminAuditLog.ps1 -Level Warning -Last 0 -PassThru | Out-GridView
```

## Programmablaufplan (PAP)

Symbole nach DIN 66001: Oval = Start/Ende, Rechteck = Verarbeitung,
Raute = Verzweigung, Parallelogramm = Ein-/Ausgabe, Rechteck mit Doppelrand = Unterprogramm.

### Gesamtlauf (`Invoke-AdminAuditRun`)

```mermaid
flowchart TD
    S(["Start"]) --> C[/"Konfiguration lesen<br/>(Config-JSON + Parameter)"/]
    C --> L["Diagnose-Log und Audit-Log initialisieren<br/>RunId vergeben"]
    L --> T["Zielkonto ermitteln<br/>Domänen-SID + RID 500 per ADSI"]
    T --> Q1{"Läuft das Tool unter<br/>dem Zielkonto?"}
    Q1 -- ja --> W1["Warnung vermerken"]
    Q1 -- nein --> D
    W1 --> D["DCs ermitteln, Scope auflösen<br/>Single / List / OU / AllServers + DCs"]
    D --> Q2{"Hosts gefunden?"}
    Q2 -- nein --> F1[/"Fehler melden"/] --> E1(["Ende"])
    Q2 -- ja --> K["Aktivierte Kollektoren laden"]
    K --> R[["Sammlung parallel je Host<br/>(PAP Host-Job)"]]
    R --> Q3{"Host länger als<br/>HostTimeoutSeconds?"}
    Q3 -- ja --> TO["Host-Job stoppen<br/>fertige Methoden behalten,<br/>offene = Timeout"]
    Q3 -- nein --> A
    TO --> A["Je Kollektor: Analyze<br/>Normalisieren, Aggregieren,<br/>Gegenproben abgleichen"]
    A --> Q4{"Analyse fehlerhaft?"}
    Q4 -- ja --> W2["Warnung vermerken,<br/>übrige Kollektoren weiter"]
    Q4 -- nein --> CV
    W2 --> CV["Coverage je Host × Methode<br/>aus den Methodenergebnissen"]
    CV --> O[/"Lauf als JSON speichern<br/>Audit-Log RunEnd, Zusammenfassung"/]
    O --> E2(["Ende"])
```

### Host-Job und Transport-Fallback (`Invoke-AuditHostJob` / `Invoke-AuditMethod`)

```mermaid
flowchart TD
    S(["Start Host-Job"]) --> P["Methoden planen<br/>Scope Host / DomainController"]
    P --> N{"DNS-Auflösung ok?"}
    N -- nein --> U["Alle Host-Methoden:<br/>Status Unreachable"] --> E(["Ende Host-Job"])
    N -- ja --> WQ{"Braucht eine Methode<br/>WinRM?"}
    WQ -- ja --> WS["WinRM-Sitzung öffnen,<br/>Remote-PS-Version lesen"]
    WQ -- nein --> M
    WS --> WO{"Sitzung offen?"}
    WO -- nein --> WN["Grund merken<br/>(Fallback später je Methode)"] --> M
    WO -- ja --> M
    M["Nächste Methode"] --> TR["Nächster deklarierter Transport<br/>WinRM → Rpc / Ldap"]
    TR --> KQ{"Kompatibel?<br/>MinPSVersion / MinOSVersion<br/>Modus Auto / Legacy"}
    KQ -- nein --> SK["Status Skipped<br/>mit Begründung"] --> MT
    KQ -- ja --> SQ{"Transport WinRM<br/>ohne Sitzung?"}
    SQ -- ja --> MT
    SQ -- nein --> X["Methodenskript ausführen<br/>(RemoteHelpers + Skript, read-only)"]
    X --> OK{"Erfolgreich?"}
    OK -- ja --> RS[/"Ergebnis + Remote-Logmeldungen<br/>übernehmen, Status Ok"/] --> NM
    OK -- nein --> FK{"Fehler am Transport und<br/>weiterer Transport vorhanden?"}
    FK -- ja --> TR
    FK -- nein --> ST["Status AccessDenied / Unreachable /<br/>NotSupported / Error"] --> NM
    MT{"Weiterer Transport?"} -- ja --> TR
    MT -- nein --> NM
    NM["Ergebnis in geteilten Zustand<br/>(überlebt einen Timeout)"] --> MQ{"Weitere Methoden?"}
    MQ -- ja --> M
    MQ -- nein --> CL["WinRM-Sitzung schließen"] --> E
```

## Datenflussdiagramm (DFD)

Notation: Rechteck = externe Entität, Kreis = Prozess, Zylinder = Datenspeicher,
Pfeil = Datenfluss. Gestrichelt = geplant.

### Ebene 0 – Kontext

```mermaid
flowchart LR
    U["Auditor<br/>(berechtigter Benutzer)"]
    AD["Active Directory<br/>(DCs, LDAP)"]
    H["Zielhosts<br/>(Server, DCs)"]
    CS["CrowdStrike-Export"]
    SM["SMTP-Relay"]
    P(("AdminAccountAudit"))
    ST[("Ablage<br/>runs / audit / logs")]

    U -- "Konfiguration, Scope,<br/>Sprache, Log-Level" --> P
    P -- "Funde, Diskrepanzen,<br/>Coverage, Konsolenlog" --> U
    AD -- "Zielkonto (SID), Computerobjekte,<br/>lastLogon, pwdLastSet je DC" --> P
    H -- "Security-/TS-/System-Log,<br/>ProfileList, Audit-Policy" --> P
    P -- "Läufe, Audit-Log,<br/>Diagnose-Log" --> ST
    ST -- "frühere Läufe" --> P
    CS -. "Exportdateien" .-> P
    P -. "HTML/CSV-Report" .-> SM
```

### Ebene 1 – Prozesse

```mermaid
flowchart LR
    U["Auditor"]
    AD["Active Directory"]
    H["Zielhosts"]

    P1(("1<br/>Konfiguration<br/>laden"))
    P2(("2<br/>Zielkonto und<br/>Scope ermitteln"))
    P3(("3<br/>Sammeln<br/>(Runner)"))
    P4(("4<br/>Analysieren und<br/>abgleichen"))
    P5(("5<br/>Speichern und<br/>ausgeben"))
    P6(("6<br/>Protokollieren"))

    D1[("D1 Config-JSON")]
    D2[("D2 Sprachdateien")]
    D3[("D3 Läufe runs/*.json")]
    D4[("D4 Audit-Log")]
    D5[("D5 Diagnose-Log")]

    U -- "Parameter" --> P1
    D1 -- "Einstellungen" --> P1
    P1 -- "effektive Konfiguration" --> P2
    AD -- "Domänen-SID, Konto,<br/>Computerobjekte, DCs" --> P2
    P2 -- "Zielkonto, Host-Liste" --> P3
    H -- "Ereignisse, Registry,<br/>Log-Zeitfenster, Audit-Policy" --> P3
    AD -- "AD-Attribute je DC" --> P3
    P3 -- "Methodenergebnisse<br/>(Status, Transport, Rohdaten)" --> P4
    D2 -- "Texte de-DE / en-US" --> P4
    P4 -- "Funde, Coverage" --> P5
    P5 -- "Lauf" --> D3
    P5 -- "Zusammenfassung, CSV" --> U
    P1 & P2 & P3 & P4 & P5 -- "Ereignisse mit Level" --> P6
    P3 -- "Remote-Logmeldungen" --> P6
    P6 -- "wer / wann / was" --> D4
    P6 -- "gefiltert nach Level" --> D5
    D5 -- "Show-AdminAuditLog" --> U
```

## Tests

```powershell
powershell.exe -NoProfile -File .\tests\Test-AdminAudit.ps1
pwsh -NoProfile -File ./tests/Test-AdminAudit.ps1      # geht auch unter Linux
```

Die Tests prüfen alles, was ohne Domäne geht: PS-2.0-Kompatibilität der Remote-Skripte,
vollständige Übersetzungen, Schema, Kontozuordnung, Abgleichslogik, Event-Parser,
die komplette Logon-Analyse mit synthetischen Ereignissen, das Diagnose-Log
(Level, Formate, Maskierung, Rotation, parallele Schreiber) sowie den Runner
(Fallback, Fehlerkapselung, Timeout, Kompatibilitätsmodus).

## Dokumentation

- [README.html](README.html) – diese Seite als eigenständige HTML-Datei, Diagramme als eingebettete Grafik
  (offline lesbar, kein Skript nötig). Nach Änderungen an der README neu erzeugen:
  `python3 tools/build_readme_html.py` (braucht pandoc und Mermaid-CLI)
- [docs/Design.md](docs/Design.md) – Architektur, Datenmodell, Kollektor-Vertrag, Abgleichsregeln
- [docs/Rechte-und-Voraussetzungen.md](docs/Rechte-und-Voraussetzungen.md) – Rechte, Ports, Verhalten bei Fehlern
- [Collectors/_Template.Collector.ps1](Collectors/_Template.Collector.ps1) – Vorlage für neue Kollektoren
