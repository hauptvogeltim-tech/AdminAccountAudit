# Vorlage fuer einen neuen Kollektor. Datei kopieren als <Name>.Collector.ps1 (ohne '_').
# Referenzimplementierung: Logon.Collector.ps1
#
# Vertrag:
#   - Die Datei gibt ein Manifest (Hashtable) zurueck.
#   - Methods[].Script laeuft auf dem Zielhost (WinRM) oder lokal mit $ComputerName (Rpc/Ldap).
#     Es muss PowerShell-2.0-kompatibel und ausschliesslich lesend sein und genau ein Objekt aus
#     New-AuditRemoteResult zurueckgeben (Records, WindowStart/End, Preconditions, Notes).
#     Zeitpunkte als ISO-String (ConvertTo-AuditRemoteIso). Fehler einfach werfen - der Runner
#     kapselt sie als Coverage-Status (AccessDenied/Unreachable/NotSupported/Error).
#     "Nicht vorhanden" (z. B. Feature fehlt) mit throw 'AUDIT_NOTSUPPORTED: ...' melden.
#   - Analyze laeuft lokal, bekommt alle Methodenergebnisse und liefert Funde (New-AuditFinding).
#     Abgleich ueber Compare-AuditTimeline / Compare-AuditPointInTime / Compare-AuditKeyedSet.
#   - Coverage-Datensaetze erzeugt der Kern automatisch - der Kollektor muss sich nicht darum kuemmern.
#   - Neue Detail-/Notiz-Texte in Localization\de-DE.json und en-US.json eintragen.

@{
    Name    = 'Example'
    Version = '0.1.0'

    Methods = @(
        @{
            Name       = 'PrimaryMethod'
            Role       = 'Primary'          # Primary | CrossCheck
            Scope      = 'Host'             # Host | DomainController
            Transports = @('WinRM', 'Rpc')  # Reihenfolge = Fallback-Reihenfolge
            Script     = {
                param($ComputerName, $Target, $Options)
                $res = New-AuditRemoteResult
                # ... lesen, filtern auf $Target.Sid / $Target.SamAccountName ...
                # [void]$res.Records.Add(@{ Key = '...'; Account = '...' })
                $res.WindowEnd = ConvertTo-AuditRemoteIso (Get-Date)
                $res
            }
        }
        @{
            Name       = 'IndependentCheck'
            Role       = 'CrossCheck'
            Scope      = 'Host'
            Transports = @('WinRM', 'Rpc')
            Script     = {
                param($ComputerName, $Target, $Options)
                New-AuditRemoteResult
            }
        }
    )

    Analyze = {
        param($Context, $MethodResults, $Target, $Options, $Hosts)
        foreach ($hn in @($MethodResults | ForEach-Object { $_.Host } | Sort-Object -Unique)) {
            $p = $MethodResults | Where-Object { $_.Host -eq $hn -and $_.Method -eq 'PrimaryMethod' }
            $s = $MethodResults | Where-Object { $_.Host -eq $hn -and $_.Method -eq 'IndependentCheck' }
            if (-not $p -or $p.Status -ne 'Ok') { continue }
            $cmp = Compare-AuditKeyedSet -Primary @($p.Result.Records) -Secondary @($(if ($s.Status -eq 'Ok') { $s.Result.Records })) `
                -KeySelector { param($r) $r.Key } -Fields @('Account') -SecondaryAvailable ($s.Status -eq 'Ok')
            foreach ($c in $cmp) {
                # New-AuditFinding -Source 'Example' -HostName $hn ... -CrossCheck $c.State
            }
        }
    }
}
