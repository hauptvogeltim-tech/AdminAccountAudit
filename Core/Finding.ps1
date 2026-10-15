# Einheitliches Datenmodell: AuditFinding, AuditCoverage, AuditRun.
# Siehe docs/Design.md, Abschnitt 3.

$script:AuditFindingFields = @(
    # Pflichtfelder laut Anforderung - stehen immer vorne
    'Source', 'Host', 'Account', 'ObjectType', 'Detail', 'Timestamp', 'Method', 'Confidence',
    # Provenienz und Abgleich
    'FindingId', 'RunId', 'CollectedAt', 'CollectedBy', 'CollectorVersion',
    'AccountSid', 'AccountScope', 'AccountMatch',
    'CorrelationKey', 'CrossCheck', 'CrossCheckNote',
    'DetailKey', 'DetailArgs', 'Attributes', 'Evidence'
)

$script:AuditEnums = @{
    Confidence   = @('High', 'Medium', 'Low')
    AccountScope = @('Domain', 'Local', 'Unresolved')
    AccountMatch = @('Sid', 'Name', 'Ambiguous')
    # Confirmed     : beide Methoden sehen dasselbe
    # Partial       : aggregierter Fund, nur ein Teil der Einzelereignisse bestaetigt
    # OnlyPrimary   : Gegenprobe lief und deckt den Zeitraum ab, sieht es aber nicht
    # OnlySecondary : nur die Gegenprobe sieht es
    # Conflict      : Quellen widersprechen sich inhaltlich
    # NotChecked    : keine unabhaengige Zweitquelle oder ausserhalb ihres Zeitfensters
    # Unverifiable  : Zweitquelle existiert, war aber nicht verfuegbar (Fehler/Unerreichbar)
    CrossCheck   = @('Confirmed', 'Partial', 'OnlyPrimary', 'OnlySecondary', 'Conflict', 'NotChecked', 'Unverifiable')
    CoverageStatus = @('Ok', 'Unreachable', 'AccessDenied', 'Timeout', 'NotSupported', 'Error', 'Skipped')
}

# Abgleich-Zustaende, die im Report als Diskrepanz gelten.
$script:AuditDiscrepancyStates = @('Partial', 'OnlyPrimary', 'OnlySecondary', 'Conflict')

function Get-AuditEnum {
    param([Parameter(Mandatory)][string]$Name)
    $script:AuditEnums[$Name]
}

function Test-AuditDiscrepancy {
    param([Parameter(Mandatory)][object]$Finding)
    $script:AuditDiscrepancyStates -contains $Finding.CrossCheck
}

function Get-AuditConfidence {
    <#
      Feste Definition (Design.md 3.4):
        High   : SID-Treffer und Cross-Check Confirmed - oder autoritative Einzelquelle per SID
        Low    : Ambiguous, Conflict, oder reiner Namens-Treffer ohne jede Bestaetigung
        Medium : alles andere
    #>
    param(
        [Parameter(Mandatory)][string]$AccountMatch,
        [Parameter(Mandatory)][string]$CrossCheck,
        [switch]$Authoritative
    )
    if ($AccountMatch -eq 'Ambiguous' -or $CrossCheck -eq 'Conflict') { return 'Low' }
    if ($AccountMatch -eq 'Sid') {
        if ($CrossCheck -eq 'Confirmed') { return 'High' }
        if ($Authoritative -and $CrossCheck -eq 'NotChecked') { return 'High' }
        return 'Medium'
    }
    # Namens-Treffer mit eindeutigem Domaenenkontext
    return 'Medium'
}

function New-AuditFinding {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Account,
        [Parameter(Mandatory)][string]$ObjectType,
        [Parameter(Mandatory)][string]$DetailKey,
        [object[]]$DetailArgs = @(),
        [object]$Timestamp,
        [Parameter(Mandatory)][string]$Method,
        [string]$Confidence,
        [Parameter(Mandatory)][hashtable]$Context,
        [string]$AccountSid,
        [string]$AccountScope = 'Unresolved',
        [string]$AccountMatch = 'Ambiguous',
        [string]$CorrelationKey = '',
        [string]$CrossCheck = 'NotChecked',
        [string]$CrossCheckNote = '',
        [string]$CrossCheckNoteKey = '',
        [object[]]$CrossCheckNoteArgs = @(),
        [switch]$Authoritative,
        [hashtable]$Attributes = @{},
        [object[]]$Evidence = @()
    )
    if (-not $Confidence) {
        $Confidence = Get-AuditConfidence -AccountMatch $AccountMatch -CrossCheck $CrossCheck -Authoritative:$Authoritative
    }
    $argsNeutral = ConvertTo-AuditDetailArgument $DetailArgs
    if ($CrossCheckNoteKey) {
        # Schluessel + Argumente in Attributes, damit die Notiz nach Sprachwechsel neu gerendert werden kann
        $noteArgs = ConvertTo-AuditDetailArgument $CrossCheckNoteArgs
        $Attributes['CrossCheckNoteKey'] = $CrossCheckNoteKey
        $Attributes['CrossCheckNoteArgs'] = $noteArgs
        $CrossCheckNote = Get-AuditString -Key $CrossCheckNoteKey -Arguments $noteArgs
    }
    $ts = $null
    if ($null -ne $Timestamp) { $ts = ConvertFrom-AuditTimeString $Timestamp }

    $f = [ordered]@{
        Source           = $Source
        Host             = $HostName
        Account          = $Account
        ObjectType       = $ObjectType
        Detail           = Get-AuditString -Key $DetailKey -Arguments $argsNeutral
        Timestamp        = $ts
        Method           = $Method
        Confidence       = $Confidence
        FindingId        = New-AuditId
        RunId            = $Context.RunId
        CollectedAt      = $Context.CollectedAt
        CollectedBy      = $Context.CollectedBy
        CollectorVersion = $Context.CollectorVersion
        AccountSid       = $AccountSid
        AccountScope     = $AccountScope
        AccountMatch     = $AccountMatch
        CorrelationKey   = $CorrelationKey
        CrossCheck       = $CrossCheck
        CrossCheckNote   = $CrossCheckNote
        DetailKey        = $DetailKey
        DetailArgs       = $argsNeutral
        Attributes       = $Attributes
        Evidence         = @($Evidence)
    }
    $obj = [pscustomobject]$f
    $obj.PSObject.TypeNames.Insert(0, 'AdminAudit.Finding')
    $obj
}

function Update-AuditFindingDetail {
    # Rendert Detail neu, z. B. nach Sprachwechsel in der GUI.
    param([Parameter(Mandatory, ValueFromPipeline)][object]$Finding, [string]$Language = (Get-AuditLanguage))
    process {
        $Finding.Detail = Get-AuditString -Key $Finding.DetailKey -Arguments @($Finding.DetailArgs) -Language $Language
        $noteKey = Get-AuditProperty $Finding.Attributes 'CrossCheckNoteKey'
        if ($noteKey) {
            $Finding.CrossCheckNote = Get-AuditString -Key $noteKey -Arguments @(Get-AuditProperty $Finding.Attributes 'CrossCheckNoteArgs' @()) -Language $Language
        }
        $Finding
    }
}

function Test-AuditFinding {
    # Liefert eine Liste von Schemaverletzungen (leer = gueltig).
    param([Parameter(Mandatory)][object]$Finding)
    $errors = New-Object System.Collections.ArrayList
    $names = @($Finding.PSObject.Properties | ForEach-Object { $_.Name })
    for ($i = 0; $i -lt $script:AuditFindingFields.Count; $i++) {
        $field = $script:AuditFindingFields[$i]
        if ($names -notcontains $field) { [void]$errors.Add("missing field '$field'") }
    }
    for ($i = 0; $i -lt 8; $i++) {
        if ($names.Count -gt $i -and $names[$i] -ne $script:AuditFindingFields[$i]) {
            [void]$errors.Add("field order: expected '$($script:AuditFindingFields[$i])' at position $i, got '$($names[$i])'")
            break
        }
    }
    foreach ($req in @('Source', 'Host', 'ObjectType', 'Detail', 'Method', 'RunId', 'CollectedAt', 'CollectedBy')) {
        if ($names -contains $req -and [string]::IsNullOrWhiteSpace([string]$Finding.$req)) {
            [void]$errors.Add("empty field '$req'")
        }
    }
    foreach ($enumField in @('Confidence', 'AccountScope', 'AccountMatch', 'CrossCheck')) {
        if ($names -contains $enumField -and $script:AuditEnums[$enumField] -notcontains $Finding.$enumField) {
            [void]$errors.Add("invalid $enumField '$($Finding.$enumField)'")
        }
    }
    ,$errors.ToArray()
}

function New-AuditCoverage {
    <#
      Ein Datensatz pro Host x Kollektor x Methode - auch bei 0 Treffern.
      Nur so ist "0 Treffer" von "nicht pruefbar" unterscheidbar.
    #>
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][string]$Method,
        [string]$Role = 'Primary',
        [Parameter(Mandatory)][string]$Status,
        [string]$Transport = '',
        [int]$ResultCount = 0,
        [object]$WindowStart,
        [object]$WindowEnd,
        [bool]$Truncated = $false,
        [hashtable]$Preconditions = @{},
        [string]$Message = '',
        [object]$StartedAt,
        [object]$EndedAt,
        [string]$CollectedBy = ''
    )
    if ($script:AuditEnums.CoverageStatus -notcontains $Status) { throw "invalid coverage status '$Status'" }
    $obj = [pscustomobject][ordered]@{
        RunId         = $RunId
        Source        = $Source
        Host          = $HostName
        Method        = $Method
        Role          = $Role
        Status        = $Status
        Transport     = $Transport
        ResultCount   = $ResultCount
        WindowStart   = ConvertFrom-AuditTimeString $WindowStart
        WindowEnd     = ConvertFrom-AuditTimeString $WindowEnd
        Truncated     = $Truncated
        Preconditions = $Preconditions
        Message       = $Message
        StartedAt     = ConvertFrom-AuditTimeString $StartedAt
        EndedAt       = ConvertFrom-AuditTimeString $EndedAt
        CollectedBy   = $CollectedBy
    }
    $obj.PSObject.TypeNames.Insert(0, 'AdminAudit.Coverage')
    $obj
}

function New-AuditEvidence {
    # Ein Rohbeleg: welche Methode hat was wann wo gesehen.
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$HostName,
        [string]$Role = 'Primary',
        [string]$Transport = '',
        [object]$Record
    )
    [ordered]@{
        Method    = $Method
        Role      = $Role
        Host      = $HostName
        Transport = $Transport
        Record    = $Record
    }
}
