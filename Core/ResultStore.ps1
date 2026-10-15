# Ergebnisse je Lauf als JSON speichern, laden und zusammenfuehren.
#
# Security-Logs auf DCs rollen oft nach Stunden bis Tagen ueber. Ein belastbares Bild
# entsteht erst aus mehreren Laeufen - deshalb koennen Laeufe zusammengefuehrt werden.

$script:AuditTimeFields = @('Timestamp', 'CollectedAt', 'WindowStart', 'WindowEnd', 'StartedAt', 'EndedAt')

function ConvertTo-AuditSerializable {
    # DateTime -> ISO-String, Objekte -> geordnete Dictionaries (rekursiv), fuer ConvertTo-Json.
    param([object]$InputObject, [int]$Depth = 0)
    if ($null -eq $InputObject) { return $null }
    if ($Depth -gt 20) { return [string]$InputObject }
    if ($InputObject -is [datetime]) { return ConvertTo-AuditIsoString $InputObject }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $InputObject.Keys) { $h[[string]$k] = ConvertTo-AuditSerializable $InputObject[$k] ($Depth + 1) }
        return $h
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($i in $InputObject) { [void]$list.Add((ConvertTo-AuditSerializable $i ($Depth + 1))) }
        return ,($list.ToArray())
    }
    $h = [ordered]@{}
    foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-AuditSerializable $p.Value ($Depth + 1) }
    return $h
}

function New-AuditRun {
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][datetime]$StartedAt,
        [datetime]$EndedAt = (Get-AuditUtcNow),
        [string]$StartedBy = '',
        [string]$ToolVersion = '',
        [hashtable]$Scope = @{},
        [object[]]$Hosts = @(),
        [hashtable]$Target = @{},
        [string[]]$Collectors = @(),
        [string[]]$Warnings = @(),
        [object[]]$Findings = @(),
        [object[]]$Coverage = @()
    )
    $run = [pscustomobject][ordered]@{
        RunId        = $RunId
        StartedAt    = $StartedAt
        EndedAt      = $EndedAt
        StartedBy    = $StartedBy
        Machine      = [System.Environment]::MachineName
        ToolVersion  = $ToolVersion
        Scope        = $Scope
        Hosts        = @($Hosts)
        Target       = $Target
        Collectors   = @($Collectors)
        Warnings     = @($Warnings)
        Findings     = @($Findings)
        Coverage     = @($Coverage)
    }
    $run.PSObject.TypeNames.Insert(0, 'AdminAudit.Run')
    $run
}

function Save-AuditRun {
    param([Parameter(Mandatory)][object]$Run, [Parameter(Mandatory)][string]$Directory)
    $dir = Expand-AuditPath $Directory
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $stamp = ([datetime]$Run.StartedAt).ToLocalTime().ToString('yyyyMMdd-HHmmss')
    $file = Join-Path $dir ("run-$stamp-" + $Run.RunId.Substring(0, 8) + '.json')
    $json = ConvertTo-Json -InputObject (ConvertTo-AuditSerializable $Run) -Depth 30
    [System.IO.File]::WriteAllText($file, $json, (New-Object System.Text.UTF8Encoding($false)))
    $file
}

function ConvertFrom-AuditStoredObject {
    # Gespeicherte Fund-/Coverage-Objekte zurueck in PSCustomObjects mit DateTime und Hashtables.
    param([object]$Object, [string]$TypeName)
    $h = [ordered]@{}
    foreach ($p in $Object.PSObject.Properties) {
        $v = $p.Value
        if ($script:AuditTimeFields -contains $p.Name) { $v = ConvertFrom-AuditTimeString $v }
        elseif ($p.Name -in @('Attributes', 'Preconditions')) { $v = ConvertTo-AuditHashtable $v; if ($null -eq $v) { $v = @{} } }
        elseif ($p.Name -in @('Evidence', 'DetailArgs')) { $v = @(ConvertTo-AuditHashtable $v) }
        $h[$p.Name] = $v
    }
    $o = [pscustomobject]$h
    if ($TypeName) { $o.PSObject.TypeNames.Insert(0, $TypeName) }
    $o
}

function Import-AuditRun {
    param([Parameter(Mandatory)][string]$Path)
    $json = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    $raw = $json | ConvertFrom-Json
    New-AuditRun -RunId $raw.RunId -StartedAt (ConvertFrom-AuditTimeString $raw.StartedAt) `
        -EndedAt (ConvertFrom-AuditTimeString $raw.EndedAt) -StartedBy $raw.StartedBy -ToolVersion $raw.ToolVersion `
        -Scope (ConvertTo-AuditHashtable $raw.Scope) -Hosts @(ConvertTo-AuditHashtable $raw.Hosts) `
        -Target (ConvertTo-AuditHashtable $raw.Target) -Collectors @($raw.Collectors) -Warnings @($raw.Warnings) `
        -Findings @($raw.Findings | ForEach-Object { ConvertFrom-AuditStoredObject $_ 'AdminAudit.Finding' }) `
        -Coverage @($raw.Coverage | ForEach-Object { ConvertFrom-AuditStoredObject $_ 'AdminAudit.Coverage' })
}

function Merge-AuditRun {
    <#
      Fuehrt mehrere Laeufe zu einer Sicht zusammen. Funde bleiben einzeln erhalten (jeder traegt
      seine RunId). Identische Ereignis-Aggregate (gleicher Host, Objekttyp, EventId und dieselben
      RecordIds - unabhaengig vom Transport) werden nur einmal gefuehrt, der juengste Lauf gewinnt.
      Teilweise ueberlappende Aggregate bleiben getrennt erhalten.
    #>
    param([Parameter(Mandatory)][object[]]$Runs)
    $seen = @{}
    $findings = New-Object System.Collections.ArrayList
    foreach ($run in @($Runs | Sort-Object { $_.StartedAt } -Descending)) {
        foreach ($f in @($run.Findings)) {
            $ids = Get-AuditProperty $f.Attributes 'RecordIds'
            if ($ids) {
                $key = $f.Host + '|' + $f.ObjectType + '|' + (Get-AuditProperty $f.Attributes 'EventId') + '|' + ((@($ids) | Sort-Object) -join ',')
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
            }
            [void]$findings.Add($f)
        }
    }
    @{
        Runs     = @($Runs | ForEach-Object { $_.RunId })
        Findings = $findings.ToArray()
        Coverage = @($Runs | ForEach-Object { $_.Coverage })
    }
}
