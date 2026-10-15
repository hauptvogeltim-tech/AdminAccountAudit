# Zielkonto: Aufloesung und Zuordnung von Fundstellen.
#
# Das Konto wird ueber die SID identifiziert (Domaenen-SID + RID 500). Namen dienen nur
# dazu, Fundstellen ohne SID (z. B. 4625, 4769, 4776, Dienst-StartName) zuzuordnen.
# Wichtig: Jeder Member-Server hat ein eigenes lokales "Administrator" (ebenfalls RID 500,
# aber Maschinen-SID). Das ist ein anderes Konto und wird als AccountScope 'Local' gefuehrt.

function New-AuditTargetAccount {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$SamAccountName,
        [string]$UserPrincipalName = '',
        [string]$DistinguishedName = '',
        [Parameter(Mandatory)][string]$DomainNetBios,
        [Parameter(Mandatory)][string]$DomainDns,
        [string]$DomainDn = '',
        [string]$DomainSid = ''
    )
    $t = @{
        Sid               = $Sid
        SamAccountName    = $SamAccountName
        UserPrincipalName = $UserPrincipalName
        DistinguishedName = $DistinguishedName
        DomainNetBios     = $DomainNetBios
        DomainDns         = $DomainDns
        DomainDn          = $DomainDn
        DomainSid         = $DomainSid
        Display           = ($DomainNetBios + '\' + $SamAccountName)
    }
    $t.NameVariants      = @(Get-AuditNameVariant -SamAccountName $SamAccountName)
    $t.KerberosVariants  = @(Get-AuditKerberosNameVariant -SamAccountName $SamAccountName -DomainDns $DomainDns -UserPrincipalName $UserPrincipalName)
    $t
}

function Get-AuditNameVariant {
    <#
      Eventlog-XPath vergleicht Werte case-sensitiv. Diese Schreibweisen decken die
      ueblichen Faelle ab (wie gespeichert, klein, gross, erster Buchstabe gross).
      Was ein Benutzer in anderer Mischschreibung eintippt, kann der XPath-Filter
      verfehlen - das steht als Hinweis in der Coverage.
    #>
    param([Parameter(Mandatory)][string]$SamAccountName)
    $v = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($SamAccountName, $SamAccountName.ToLowerInvariant(), $SamAccountName.ToUpperInvariant(),
                     ($SamAccountName.Substring(0, 1).ToUpperInvariant() + $SamAccountName.Substring(1).ToLowerInvariant()))) {
        if (-not $v.Contains($n)) { $v.Add($n) }
    }
    $v.ToArray()
}

function Get-AuditKerberosNameVariant {
    # 4769 fuehrt TargetUserName als "name@REALM".
    param([string]$SamAccountName, [string]$DomainDns, [string]$UserPrincipalName)
    $v = New-Object System.Collections.Generic.List[string]
    foreach ($n in (Get-AuditNameVariant -SamAccountName $SamAccountName)) {
        foreach ($r in @($DomainDns.ToUpperInvariant(), $DomainDns.ToLowerInvariant(), $DomainDns)) {
            $s = $n + '@' + $r
            if (-not $v.Contains($s)) { $v.Add($s) }
        }
    }
    if ($UserPrincipalName -and -not $v.Contains($UserPrincipalName)) { $v.Add($UserPrincipalName) }
    $v.ToArray()
}

function Resolve-AuditAccountMatch {
    <#
      Ordnet eine Kontoangabe aus einer Fundstelle dem Zielkonto zu.
      Rueckgabe: $null (kein Bezug zum Zielkonto) oder
                 @{ Scope = Domain|Local|Unresolved; Match = Sid|Name|Ambiguous; Display = '...' }
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Target,
        [string]$Sid,
        [string]$Name,
        [string]$Domain,
        [string]$HostShortName = '',
        [bool]$IsDomainController = $false
    )
    $validSid = $Sid -and $Sid -match '^S-1-5-'
    if ($validSid) {
        if ($Sid -eq $Target.Sid) {
            return @{ Scope = 'Domain'; Match = 'Sid'; Display = $Target.Display }
        }
        # Lokales RID-500 eines Member-Servers: andere SID, gleicher Name
        if ($Sid -match '-500$' -and $Target.DomainSid -and -not $Sid.StartsWith($Target.DomainSid + '-')) {
            $disp = if ($Domain) { $Domain + '\' + $Name } else { $Name }
            return @{ Scope = 'Local'; Match = 'Sid'; Display = $disp }
        }
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $n = $Name.Trim()
    $d = if ($Domain) { $Domain.Trim() } else { '' }
    if ($n.Contains('\')) {
        $parts = $n.Split('\', 2); if (-not $d) { $d = $parts[0] }; $n = $parts[1]
    }
    elseif ($n.Contains('@')) {
        if ($Target.UserPrincipalName -and $n -ieq $Target.UserPrincipalName) {
            return @{ Scope = 'Domain'; Match = 'Name'; Display = $Target.Display }
        }
        $parts = $n.Split('@', 2); $n = $parts[0]; if (-not $d) { $d = $parts[1] }
    }
    if ($n -ine $Target.SamAccountName) { return $null }

    $display = if ($d) { $d + '\' + $n } else { $n }
    if (-not $d -or $d -eq '-') {
        # Ein DC hat keine lokalen Konten - dort ist ein unqualifizierter Name das Domaenenkonto.
        if ($IsDomainController) { return @{ Scope = 'Domain'; Match = 'Name'; Display = $Target.Display } }
        return @{ Scope = 'Unresolved'; Match = 'Ambiguous'; Display = $display }
    }
    if ($d -ieq $Target.DomainNetBios -or $d -ieq $Target.DomainDns) {
        return @{ Scope = 'Domain'; Match = 'Name'; Display = $Target.Display }
    }
    if ($d -eq '.' -or ($HostShortName -and $d -ieq $HostShortName)) {
        return @{ Scope = 'Local'; Match = 'Name'; Display = $display }
    }
    return @{ Scope = 'Unresolved'; Match = 'Ambiguous'; Display = $display }
}

function ConvertTo-AuditLdapSidFilter {
    # SID -> LDAP-Filterwert (\01\05...), fuer DirectorySearcher.
    param([Parameter(Mandatory)][string]$Sid)
    $s = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $bytes = New-Object byte[] $s.BinaryLength
    $s.GetBinaryForm($bytes, 0)
    ($bytes | ForEach-Object { '\{0:x2}' -f $_ }) -join ''
}

function Resolve-AuditTargetAccount {
    <#
      Ermittelt das Zielkonto aus dem AD (ADSI, kein RSAT noetig).
      Domaenen-SID aus dem Domaenenobjekt + RID aus der Konfiguration.
    #>
    param([int]$Rid = 500, [string]$Server)
    $prefix = if ($Server) { "LDAP://$Server/" } else { 'LDAP://' }
    $rootDse = [ADSI]($prefix + 'RootDSE')
    $domainDn = [string]$rootDse.Properties['defaultNamingContext'].Value
    $configDn = [string]$rootDse.Properties['configurationNamingContext'].Value
    if (-not $domainDn) { throw 'Unable to read RootDSE (no domain connectivity?)' }

    $domainEntry = [ADSI]($prefix + $domainDn)
    $domainSid = (New-Object System.Security.Principal.SecurityIdentifier($domainEntry.Properties['objectSid'].Value, 0)).Value
    $sid = $domainSid + '-' + $Rid

    $user = [ADSI]($prefix + '<SID=' + $sid + '>')
    $sam = [string]$user.Properties['sAMAccountName'].Value
    if (-not $sam) { throw "Account with SID $sid not found" }

    $dns = (($domainDn -split ',') | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_.Substring(3) }) -join '.'

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]($prefix + 'CN=Partitions,' + $configDn)
    $searcher.Filter = "(&(objectClass=crossRef)(nCName=$domainDn))"
    [void]$searcher.PropertiesToLoad.Add('nETBIOSName')
    $res = $searcher.FindOne()
    $netbios = if ($res) { [string]$res.Properties['netbiosname'][0] } else { $dns.Split('.')[0].ToUpperInvariant() }

    New-AuditTargetAccount -Sid $sid -SamAccountName $sam `
        -UserPrincipalName ([string]$user.Properties['userPrincipalName'].Value) `
        -DistinguishedName ([string]$user.Properties['distinguishedName'].Value) `
        -DomainNetBios $netbios -DomainDns $dns -DomainDn $domainDn -DomainSid $domainSid
}
