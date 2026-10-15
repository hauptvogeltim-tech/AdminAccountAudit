# Reichweite: gegen welche Hosts wird gesammelt?
# Modi: Single | List | OU | AllComputers | AllServers. DCs werden standardmaessig immer
# ergaenzt, weil Kerberos/NTLM-Ereignisse (4768/4769/4776) nur dort stehen.

$script:AuditUacDisabled = 2
$script:AuditUacServerTrust = 8192

function New-AuditHostInfo {
    param(
        [Parameter(Mandatory)][string]$Name,
        [bool]$IsDomainController = $false,
        [string]$OperatingSystem = '',
        [string]$OperatingSystemVersion = '',
        [bool]$Enabled = $true,
        [string]$Origin = ''
    )
    @{
        Name                   = $Name
        ShortName              = $Name.Split('.')[0]
        IsDomainController     = $IsDomainController
        OperatingSystem        = $OperatingSystem
        OperatingSystemVersion = $OperatingSystemVersion
        Enabled                = $Enabled
        Origin                 = $Origin
    }
}

function ConvertFrom-AuditComputerSearchResult {
    param([Parameter(Mandatory)][object]$Result, [string]$Origin)
    $p = $Result.Properties
    $name = [string]($p['dnshostname'] | Select-Object -First 1)
    if (-not $name) { $name = [string]($p['name'] | Select-Object -First 1) }
    $uac = [int]($p['useraccountcontrol'] | Select-Object -First 1)
    New-AuditHostInfo -Name $name `
        -IsDomainController (($uac -band $script:AuditUacServerTrust) -ne 0) `
        -OperatingSystem ([string]($p['operatingsystem'] | Select-Object -First 1)) `
        -OperatingSystemVersion ([string]($p['operatingsystemversion'] | Select-Object -First 1)) `
        -Enabled (($uac -band $script:AuditUacDisabled) -eq 0) -Origin $Origin
}

function Find-AuditComputer {
    param([string]$LdapFilter = '(objectCategory=computer)', [string]$SearchBase, [string]$Origin = 'AD')
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($SearchBase) { $searcher.SearchRoot = [ADSI]('LDAP://' + $SearchBase) }
    $searcher.Filter = $LdapFilter
    $searcher.PageSize = 500
    foreach ($a in @('dNSHostName', 'name', 'operatingSystem', 'operatingSystemVersion', 'userAccountControl')) {
        [void]$searcher.PropertiesToLoad.Add($a)
    }
    $results = $searcher.FindAll()
    try {
        foreach ($r in $results) { ConvertFrom-AuditComputerSearchResult -Result $r -Origin $Origin }
    }
    finally { $results.Dispose() }
}

function Get-AuditDomainController {
    Find-AuditComputer -LdapFilter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' -Origin 'DomainController'
}

function Resolve-AuditScope {
    <#
      Liefert eindeutige Host-Infos (Hashtables). Hosts aus Single/List werden, wenn
      moeglich, im AD nachgeschlagen (fuer OS-Version und DC-Kennung); nicht gefundene
      Namen bleiben mit Origin 'Manual' erhalten statt still zu verschwinden.
    #>
    param([Parameter(Mandatory)][hashtable]$ScopeConfig, [object[]]$DomainControllers)
    $mode = [string]$ScopeConfig.Mode
    $hosts = New-Object System.Collections.ArrayList

    switch ($mode) {
        { $_ -in 'Single', 'List' } {
            foreach ($h in @($ScopeConfig.Hosts)) {
                if ([string]::IsNullOrWhiteSpace($h)) { continue }
                $short = $h.Split('.')[0]
                $found = @(Find-AuditComputer -LdapFilter "(&(objectCategory=computer)(name=$short))" -Origin $mode)
                if ($found.Count -gt 0) { [void]$hosts.Add($found[0]) }
                else { [void]$hosts.Add((New-AuditHostInfo -Name $h -Origin 'Manual')) }
            }
        }
        'OU' {
            if (-not $ScopeConfig.SearchBase) { throw 'Scope mode OU requires SearchBase' }
            foreach ($h in Find-AuditComputer -SearchBase $ScopeConfig.SearchBase -Origin 'OU') { [void]$hosts.Add($h) }
        }
        'AllComputers' {
            foreach ($h in Find-AuditComputer -Origin 'AllComputers') { [void]$hosts.Add($h) }
        }
        'AllServers' {
            foreach ($h in Find-AuditComputer -LdapFilter '(&(objectCategory=computer)(operatingSystem=*Server*))' -Origin 'AllServers') { [void]$hosts.Add($h) }
        }
        default { throw "Unknown scope mode '$mode'" }
    }

    if ($ScopeConfig.IncludeDomainControllers) {
        if ($null -eq $DomainControllers) { $DomainControllers = @(Get-AuditDomainController) }
        foreach ($dc in $DomainControllers) { [void]$hosts.Add($dc) }
    }

    Select-AuditUniqueHost -Hosts $hosts.ToArray() -OnlyEnabled ([bool]$ScopeConfig.OnlyEnabled)
}

function Select-AuditUniqueHost {
    param([object[]]$Hosts, [bool]$OnlyEnabled = $true)
    $seen = @{}
    foreach ($h in $Hosts) {
        if ($null -eq $h) { continue }
        if ($OnlyEnabled -and -not $h.Enabled) { continue }
        $key = $h.Name.ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            if ($h.IsDomainController) { $seen[$key].IsDomainController = $true }
            continue
        }
        $seen[$key] = $h
        $h
    }
}
