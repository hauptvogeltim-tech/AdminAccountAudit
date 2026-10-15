# Rechte und Voraussetzungen

Das Tool liest nur. Es ändert weder Audit-Policy noch Log-Größen, Dienste oder Konten.
Alles unten Genannte muss deshalb vorhanden sein; das Tool richtet es nicht ein.

## Audit-Arbeitsplatz

- Domänenmitglied mit **Windows PowerShell 5.1**. RSAT ist für die bisherigen Kollektoren nicht nötig.
- Start mit der Identität, deren Rechte genutzt werden sollen (Kerberos, keine Passwortabfrage).
  **Nicht als `Administrator` starten.** Das Tool warnt sonst, weil die eigenen Anmeldungen das Ergebnis verfälschen.

## Rechte der ausführenden Identität

| Ziel | Benötigt für | Recht |
|---|---|---|
| Member-Server | WinRM-Sitzung, `auditpol`, Security-Log, Registry | Lokaler Administrator (Standard-WinRM-Endpunkt) |
| Member-Server, nur RPC | Security-/System-/TS-Logs per RPC | Mitglied *Event Log Readers* oder lokaler Admin |
| Member-Server, nur RPC | ProfileList per Remote-Registry, NTUSER.DAT per `C$` | Lokaler Administrator |
| DCs | WinRM + Security-Log | *Domain Admins* oder *Remote Management Users* + *Event Log Readers* (für `auditpol` ist Admin nötig) |
| DCs | AD-Attribute per LDAP | *Authenticated Users* genügt (`lastLogon`, `badPasswordTime`, `msDS-ReplAttributeMetaData` sind lesbar) |

## Netzwerk

| Transport | Ports | Voraussetzung am Ziel |
|---|---|---|
| WinRM (bevorzugt) | TCP 5985 (HTTP) / 5986 (HTTPS) | WinRM-Dienst + Listener. Auf Server 2008 erst ab WMF 2.0. |
| RPC (Fallback) | TCP 135 + dynamische Ports 49152–65535 | Firewall-Regelgruppe „Remote-Ereignisprotokollverwaltung“, für ProfileList der Dienst *Remoteregistrierung* |
| SMB | TCP 445 | Admin-Freigabe `C$` (nur NTUSER.DAT-Zeitstempel im RPC-Modus) |
| LDAP | TCP 389 | zu jedem DC |

## Verhalten bei Problemen

Jedes Problem landet als Status im Coverage-Datensatz. Es wird nie als „nichts gefunden“ gewertet.

| Situation | Status | Folge |
|---|---|---|
| Name nicht auflösbar | `Unreachable` (DNS) | alle Host-Methoden dieses Hosts |
| WinRM nicht erreichbar | Fallback auf RPC; Grund steht in `Message` | `Transport = Rpc` |
| WinRM und RPC nicht erreichbar | `Unreachable` | |
| Rechte fehlen | `AccessDenied` | kein Fallback auf einen anderen Transport |
| Log/Feature fehlt (z. B. TS-Logs auf 2008) | `NotSupported` | betroffene Gegenproben werden `Unverifiable` |
| Host braucht länger als `HostTimeoutSeconds` | `Timeout` für die noch offenen Methoden | bereits fertige Methoden bleiben erhalten |
| Log geleert | `Preconditions.LastCleared` (+ wer) | Zeitfenster beginnt danach |
| Ergebnis bei `MaxEventsPerQuery` abgeschnitten | `Truncated = true` | Zeitfenster beginnt beim ältesten gelieferten Ereignis |

Funde, deren Gegenquelle fehlte, tragen `CrossCheck = Unverifiable`.

## Empfehlungen für aussagekräftige Ergebnisse

Das Tool liest diese Einstellungen nur und meldet sie. Ändern muss man sie selbst.

- **Erweiterte Überwachungsrichtlinie** (Erfolg + Fehler): Anmelden, Abmelden, Spezielle Anmeldung,
  Kontosperrung, Überprüfung der Anmeldeinformationen, Kerberos-Authentifizierungsdienst,
  Kerberos-Dienstticketvorgänge, Benutzerkontenverwaltung.
- **Security-Log auf den DCs deutlich vergrößern** (z. B. 1–4 GB). Sonst reicht das Fenster oft nur Stunden zurück.
- Das Tool **wiederholt laufen lassen** (z. B. täglich über Wochen). Die gespeicherten Läufe lassen sich zusammenführen,
  doppelte Ereignisse aus überlappenden Zeitfenstern werden dabei erkannt.
