# AdminAccountAudit

Inventarisiert **read-only** alle Abhängigkeiten vom Domänen-Administratorkonto
(Domänen-SID + RID 500): wo, wie und von wo es benutzt wird. Damit lässt sich das
Konto später kontrolliert aus dem Betrieb herauslösen.

Grundsätze: Es wird nichts verändert. Jede Aussage hat nach Möglichkeit eine zweite,
unabhängige Quelle. Jeder Fund trägt seine Herkunft. Nicht erreichbare Quellen
werden als solche gemeldet und nie als „nichts gefunden“ gewertet.

**Stand:** Kern + Kollektor `Logon` (Security-Log, DC-Authentifizierung,
TerminalServices-/Winlogon-Logs, Benutzerprofile, AD-Attribute je DC).
GUI, Reporting und die übrigen Kollektoren folgen.

## Testlauf

Windows PowerShell 5.1, mit einem berechtigten Konto (nicht `Administrator`):

```powershell
# alle Server laut Config + DCs
.\Invoke-AdminAudit.ps1

# nur bestimmte Hosts (DCs werden ergänzt), Ergebnis zusätzlich als CSV, englisch
.\Invoke-AdminAudit.ps1 -ComputerName srv01,srv02 -CsvPath .\funde.csv -Language en-US
```

Mit `-LegacyMode` werden alle Hosts wie Server 2008 / PowerShell 2.0 behandelt
(Abwärtskompatibilitätsmodus). Standard ist die automatische Erkennung je Host.

Jeder Lauf wird als JSON unter `%ProgramData%\AdminAccountAudit\runs` gespeichert.
Das Audit-Log des Tools liegt unter `%ProgramData%\AdminAccountAudit\audit`.

Konfiguration: `Config\AdminAudit.config.json` (Scope, Timeouts, Parallelität,
Toleranzen, SMTP). Nicht angegebene Schlüssel nehmen die Defaults aus `Core\Config.ps1`.

## Tests

```powershell
powershell.exe -NoProfile -File .\tests\Test-AdminAudit.ps1
pwsh -NoProfile -File ./tests/Test-AdminAudit.ps1      # geht auch unter Linux
```

Die Tests prüfen alles, was ohne Domäne geht: PS-2.0-Kompatibilität der Remote-Skripte,
vollständige Übersetzungen, Schema, Kontozuordnung, Abgleichslogik, Event-Parser,
die komplette Logon-Analyse mit synthetischen Ereignissen sowie den Runner
(Fallback, Fehlerkapselung, Timeout).

## Dokumentation

- [docs/Design.md](docs/Design.md) – Architektur, Datenmodell, Kollektor-Vertrag, Abgleichsregeln
- [docs/Rechte-und-Voraussetzungen.md](docs/Rechte-und-Voraussetzungen.md) – Rechte, Ports, Verhalten bei Fehlern
- [Collectors/_Template.Collector.ps1](Collectors/_Template.Collector.ps1) – Vorlage für neue Kollektoren
