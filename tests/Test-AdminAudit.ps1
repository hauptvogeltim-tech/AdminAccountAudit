<#
.SYNOPSIS
    Tests fuer AdminAccountAudit ohne Domaene und ohne Pester.

.DESCRIPTION
    Prueft alles, was ohne AD/WinRM pruefbar ist:
      - statische Regeln (ASCII-Quelltext, PowerShell-2.0-Kompatibilitaet der Remote-Skripte,
        vollstaendige Uebersetzungen)
      - Datenmodell (Schema, Confidence-Regeln, Sprachwechsel)
      - Kontozuordnung (SID / Name / lokales RID-500)
      - Abgleichslogik (Timeline, Zeitpunkt, Schluessel)
      - Event-Parser mit nachgebauten EventLogRecords
      - Logon-Analyse Ende-zu-Ende mit synthetischen Methodenergebnissen
      - Runner: Parallelitaet, Transport-Fallback, Fehlerkapselung, Timeout pro Host

    Laeuft unter Windows PowerShell 5.1 und PowerShell 7 (auch Linux).

.EXAMPLE
    pwsh -NoProfile -File AdminAccountAudit/tests/Test-AdminAudit.ps1
#>
[CmdletBinding()]
param([switch]$SkipRunner)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Import-Module (Join-Path $root 'AdminAudit.psd1') -Force

$script:Passed = 0
$script:Failed = 0
$script:Failures = New-Object System.Collections.ArrayList

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        $script:Passed++
        Write-Host ('  [ok]   ' + $Name) -ForegroundColor DarkGreen
    }
    catch {
        $script:Failed++
        [void]$script:Failures.Add($Name + ': ' + $_.Exception.Message)
        Write-Host ('  [FAIL] ' + $Name + ': ' + $_.Exception.Message) -ForegroundColor Red
    }
}

function Assert-Equal($Expected, $Actual, [string]$Message = '') {
    if ($Expected -ne $Actual) { throw "expected '$Expected', got '$Actual' $Message" }
}
function Assert-True($Condition, [string]$Message = 'condition false') {
    if (-not $Condition) { throw $Message }
}

# ---------------------------------------------------------------------------- Hilfen

$T0 = [datetime]::SpecifyKind([datetime]'2026-10-10T08:00:00', 'Utc')
$DomainSid = 'S-1-5-21-1111111111-2222222222-3333333333'
$Target = New-AuditTargetAccount -Sid "$DomainSid-500" -SamAccountName 'Administrator' `
    -DomainNetBios 'CORP' -DomainDns 'corp.local' -DomainDn 'DC=corp,DC=local' -DomainSid $DomainSid

$script:RecordId = 1000
function New-FakeEvent {
    param([int]$Id, [datetime]$Time, [hashtable]$Data = @{}, [hashtable]$UserData, [string]$Provider = 'Microsoft-Windows-Security-Auditing',
          [string]$Log = 'Security', [string]$Machine = 'srv01.corp.local', [switch]$Failure, [string]$UserSid)
    $script:RecordId++
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>')
    [void]$sb.Append('<Provider Name="' + $Provider + '"/><EventID>' + $Id + '</EventID></System>')
    if ($UserData) {
        [void]$sb.Append('<UserData><EventXML xmlns="Event_NS">')
        foreach ($k in $UserData.Keys) { [void]$sb.Append("<$k>" + [System.Security.SecurityElement]::Escape([string]$UserData[$k]) + "</$k>") }
        [void]$sb.Append('</EventXML></UserData>')
    }
    else {
        [void]$sb.Append('<EventData>')
        foreach ($k in $Data.Keys) { [void]$sb.Append('<Data Name="' + $k + '">' + [System.Security.SecurityElement]::Escape([string]$Data[$k]) + '</Data>') }
        [void]$sb.Append('</EventData>')
    }
    [void]$sb.Append('</Event>')
    $xml = $sb.ToString()
    $kw = if ($Failure) { [int64]0x0010000000000000 } else { [int64]0x0020000000000000 }
    $o = New-Object psobject -Property @{
        Id = $Id; RecordId = [int64]$script:RecordId; TimeCreated = $Time; MachineName = $Machine
        ProviderName = $Provider; LogName = $Log; Keywords = $kw
        UserId = $(if ($UserSid) { New-Object psobject -Property @{ Value = $UserSid } } else { $null })
    }
    $o | Add-Member -MemberType ScriptMethod -Name ToXml -Value ([scriptblock]::Create("'" + $xml.Replace("'", "''") + "'"))
    $o
}
function New-Rec { ConvertFrom-AuditEventRecord (New-FakeEvent @args) }

function New-FakeMethodResult {
    param([string]$HostName, [string]$Method, [string]$Role = 'CrossCheck', [string]$Status = 'Ok', [object[]]$Records = @(),
          [object]$WindowStart, [hashtable]$HostInfo, [string]$Transport = 'WinRM')
    $res = $null
    if ($Status -eq 'Ok') {
        $res = New-AuditRemoteResult
        foreach ($r in $Records) { [void]$res.Records.Add($r) }
        $res.WindowStart = ConvertTo-AuditIsoString $WindowStart
        $res.WindowEnd = ConvertTo-AuditIsoString ($T0.AddDays(3))
    }
    @{ Collector = 'Logon'; CollectorVersion = '1.0.0'; Method = $Method; Role = $Role; Host = $HostName; HostInfo = $HostInfo
       Transport = $Transport; Status = $Status; Message = ''; TransportNotes = @(); StartedAt = $T0; EndedAt = $T0; Result = $res }
}

$Context = @{ RunId = 'test-run'; CollectedAt = $T0; CollectedBy = 'CORP\auditor'; CollectorVersion = '1.0.0'; Source = 'Logon' }

# ============================================================================ Statische Regeln
Write-Host 'Static rules'

Test-Case 'all script files are ASCII (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
    $bad = @(Get-ChildItem -LiteralPath $root -Recurse -Include *.ps1, *.psm1, *.psd1, *.cmd | Where-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        @($bytes | Where-Object { $_ -gt 127 }).Count -gt 0
    } | ForEach-Object { $_.Name })
    Assert-Equal 0 $bad.Count ($bad -join ', ')
}

function Get-Ps2Violation {
    # Statischer Check auf Sprachmittel, die es in PowerShell 2.0 nicht gibt.
    param([System.Management.Automation.Language.Ast]$Ast, [string]$Label)
    $v = New-Object System.Collections.ArrayList
    $bannedCommands = @('Get-CimInstance', 'New-CimSession', 'Invoke-CimMethod', 'ConvertTo-Json', 'ConvertFrom-Json',
                        'Invoke-WebRequest', 'Invoke-RestMethod', 'Get-ScheduledTask', 'Get-ScheduledTaskInfo')
    foreach ($n in $Ast.FindAll({ $true }, $true)) {
        $t = $n.GetType().Name
        switch ($t) {
            'TypeExpressionAst' { if ($n.TypeName.Name -in 'pscustomobject', 'ordered') { [void]$v.Add("$Label`: [$($n.TypeName.Name)]") } }
            'ConvertExpressionAst' { if ($n.Type.TypeName.Name -in 'pscustomobject', 'ordered') { [void]$v.Add("$Label`: [$($n.Type.TypeName.Name)] cast") } }
            'InvokeMemberExpressionAst' {
                $m = [string]$n.Member
                if ($n.Static -and $m -eq 'new') { [void]$v.Add("$Label`: ::new()") }
                if ($m -in 'Where', 'ForEach') { [void]$v.Add("$Label`: .$m()") }
            }
            'BinaryExpressionAst' {
                # TokenKind: Iin/Cin/Inotin/Cnotin (-in/-notin), Shl/Shr - alles erst ab PowerShell 3.0
                if ([string]$n.Operator -match '^(I|C)?(in|notin)$|^Shl$|^Shr$') { [void]$v.Add("$Label`: -$($n.Operator)") }
            }
            'CommandAst' {
                $name = $n.GetCommandName()
                if ($name -in $bannedCommands) { [void]$v.Add("$Label`: $name") }
                $els = @($n.CommandElements)
                for ($i = 0; $i -lt $els.Count; $i++) {
                    if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst]) {
                        if ($els[$i].ParameterName -eq 'Raw' -and $name -eq 'Get-Content') { [void]$v.Add("$Label`: Get-Content -Raw") }
                        if ($els[$i].ParameterName -eq 'ErrorAction' -and $i + 1 -lt $els.Count -and [string]$els[$i + 1].Extent.Text -match 'Ignore') {
                            [void]$v.Add("$Label`: -ErrorAction Ignore")
                        }
                    }
                }
            }
            'VariableExpressionAst' { if ($n.VariablePath.UserPath -eq 'PSItem') { [void]$v.Add("$Label`: `$PSItem") } }
            'TypeDefinitionAst' { [void]$v.Add("$Label`: class") }
            'UsingStatementAst' { [void]$v.Add("$Label`: using") }
            'TernaryExpressionAst' { [void]$v.Add("$Label`: ternary") }
            'PipelineChainAst' { [void]$v.Add("$Label`: && / ||") }
        }
        if ($t -eq 'BinaryExpressionAst' -and [string]$n.Operator -eq 'QuestionQuestion') { [void]$v.Add("$Label`: ??") }
    }
    ,$v.ToArray()
}

Test-Case 'remote helpers are PowerShell 2.0 compatible' {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Core/RemoteHelpers.ps1'), [ref]$null, [ref]$null)
    $v = Get-Ps2Violation -Ast $ast -Label 'RemoteHelpers'
    Assert-Equal 0 $v.Count ($v -join '; ')
}

Test-Case 'collector method scripts are PowerShell 2.0 compatible' {
    $all = @()
    foreach ($c in Get-AuditCollector) {
        foreach ($m in $c.Methods) {
            # Methoden, die ausdruecklich PS 3+ verlangen, laufen auf aelteren Hosts nie (Runner: 'Skipped')
            if ($m.MinPSVersion -and [version]$m.MinPSVersion -ge [version]'3.0') { continue }
            $all += Get-Ps2Violation -Ast $m.Script.Ast -Label "$($c.Name)/$($m.Name)"
        }
    }
    Assert-Equal 0 $all.Count ($all -join '; ')
}

Test-Case 'the PS2 check itself detects violations' {
    $sb = { $x = [pscustomobject]@{ a = 1 }; if (1 -in @(1)) { }; Get-CimInstance Win32_Service; [System.Text.StringBuilder]::new() }
    $v = Get-Ps2Violation -Ast $sb.Ast -Label 'probe'
    Assert-True ($v.Count -ge 4) ("found only: " + ($v -join '; '))
}

Test-Case 'de-DE and en-US have the same keys' {
    $de = ConvertTo-AuditHashtable ((Get-Content -LiteralPath (Join-Path $root 'Localization/de-DE.json') -Encoding UTF8 | Out-String) | ConvertFrom-Json)
    $en = ConvertTo-AuditHashtable ((Get-Content -LiteralPath (Join-Path $root 'Localization/en-US.json') -Encoding UTF8 | Out-String) | ConvertFrom-Json)
    $diff = @(Compare-Object @($de.Keys) @($en.Keys))
    Assert-Equal 0 $diff.Count (($diff | ForEach-Object { $_.InputObject }) -join ', ')
}

Test-Case 'every string key referenced in code exists' {
    $de = ConvertTo-AuditHashtable ((Get-Content -LiteralPath (Join-Path $root 'Localization/de-DE.json') -Encoding UTF8 | Out-String) | ConvertFrom-Json)
    $missing = @()
    foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -Include *.ps1 | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' }) {
        $text = [System.IO.File]::ReadAllText($f.FullName)
        foreach ($m in [regex]::Matches($text, "'@?((?:Detail|Note|Warning|Error|Cli|Value)\.[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*)'")) {
            $k = $m.Groups[1].Value
            if ($k -match '\.$') { continue }
            if (-not $de.ContainsKey($k)) { $missing += "$($f.Name): $k" }
        }
    }
    # dynamisch zusammengesetzte Schluessel
    foreach ($cat in 'Logon', 'LogonFailed', 'Logoff', 'ExplicitCredentials', 'SpecialPrivileges', 'KerberosTGT', 'KerberosTGS',
                     'KerberosPreAuthFailed', 'NtlmValidation', 'Lockout', 'PasswordChange', 'PasswordReset', 'AccountChanged') {
        if (-not $de.ContainsKey("Detail.Event.$cat")) { $missing += "Detail.Event.$cat" }
    }
    foreach ($id in 21, 22, 23, 24, 25, 1149, 7001, 7002) { if (-not $de.ContainsKey("Detail.Session.$id")) { $missing += "Detail.Session.$id" } }
    foreach ($s in (Get-AuditEnum CrossCheck)) { if (-not $de.ContainsKey("CrossCheck.$s")) { $missing += "CrossCheck.$s" } }
    foreach ($s in (Get-AuditEnum CoverageStatus)) { if (-not $de.ContainsKey("Coverage.$s")) { $missing += "Coverage.$s" } }
    Assert-Equal 0 $missing.Count ($missing -join ', ')
}

Test-Case 'collector manifests are valid' {
    foreach ($c in Get-AuditCollector) { Assert-Equal 0 (Test-AuditCollectorManifest -Manifest $c).Count }
}

# ============================================================================ Datenmodell
Write-Host 'Data model'

Test-Case 'finding has the eight required fields first and validates' {
    Set-AuditLanguage 'de-DE'
    $f = New-AuditFinding -Source 'Logon' -HostName 'srv01' -Account 'CORP\Administrator' -ObjectType 'LogonEvent' `
        -DetailKey 'Detail.Event.Logon' -DetailArgs @(10, '@LogonType.10', '10.0.0.5', 'WS1', 1, $T0, $T0) -Timestamp $T0 `
        -Method 'SecurityLog (WinRM)' -Context $Context -AccountSid $Target.Sid -AccountScope 'Domain' -AccountMatch 'Sid' -CrossCheck 'Confirmed'
    $names = @($f.PSObject.Properties | Select-Object -First 8 | ForEach-Object { $_.Name })
    Assert-Equal 'Source,Host,Account,ObjectType,Detail,Timestamp,Method,Confidence' ($names -join ',')
    Assert-Equal 0 (Test-AuditFinding $f).Count
    Assert-Equal 'High' $f.Confidence
    Assert-True ($f.Detail -like 'Anmeldung Typ 10 (Remote-Interaktiv (RDP))*') $f.Detail
}

Test-Case 'language switch re-renders detail and note' {
    $f = New-AuditFinding -Source 'Logon' -HostName 'srv01' -Account 'x' -ObjectType 'LogonEvent' -DetailKey 'Detail.Event.Logon' `
        -DetailArgs @(2, '@LogonType.2', '', '', 1, $T0, $T0) -Method 'm' -Context $Context -CrossCheck 'NotChecked' `
        -CrossCheckNoteKey 'Note.Logon.NoSecondSource' -AccountMatch 'Sid' -AccountScope 'Domain'
    Assert-True ($f.CrossCheckNote -like 'F*r diesen*') $f.CrossCheckNote
    $f | Update-AuditFindingDetail -Language 'en-US' | Out-Null
    Assert-True ($f.Detail -like 'Logon type 2 (Interactive)*') $f.Detail
    Assert-True ($f.CrossCheckNote -like 'No independent*') $f.CrossCheckNote
}

Test-Case 'Test-AuditFinding reports schema violations' {
    $bad = [pscustomobject]@{ Source = 'x'; Host = ''; Confidence = 'Sure' }
    $e = Test-AuditFinding $bad
    Assert-True ($e.Count -ge 3) ($e -join '; ')
}

Test-Case 'confidence rules' {
    Assert-Equal 'High' (Get-AuditConfidence -AccountMatch Sid -CrossCheck Confirmed)
    Assert-Equal 'Medium' (Get-AuditConfidence -AccountMatch Sid -CrossCheck NotChecked)
    Assert-Equal 'High' (Get-AuditConfidence -AccountMatch Sid -CrossCheck NotChecked -Authoritative)
    Assert-Equal 'Medium' (Get-AuditConfidence -AccountMatch Name -CrossCheck Confirmed)
    Assert-Equal 'Low' (Get-AuditConfidence -AccountMatch Sid -CrossCheck Conflict)
    Assert-Equal 'Low' (Get-AuditConfidence -AccountMatch Ambiguous -CrossCheck Confirmed)
}

Test-Case 'coverage rejects unknown status' {
    $threw = $false
    try { New-AuditCoverage -RunId r -Source s -HostName h -Method m -Status 'Fine' | Out-Null } catch { $threw = $true }
    Assert-True $threw
}

Test-Case 'run round-trips through JSON' {
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) ('aa-test-' + [guid]::NewGuid().ToString('N'))
    try {
        $f = New-AuditFinding -Source 'Logon' -HostName 'srv01' -Account 'CORP\Administrator' -ObjectType 'LogonEvent' `
            -DetailKey 'Detail.Event.Logon' -DetailArgs @(3, '@LogonType.3', '10.0.0.9', 'X', 2, $T0, $T0) -Timestamp $T0 -Method 'm' `
            -Context $Context -AccountMatch 'Sid' -AccountScope 'Domain' -Attributes @{ RecordIds = @(1, 2); LogonType = 3 }
        $c = New-AuditCoverage -RunId 'r' -Source 'Logon' -HostName 'srv01' -Method 'SecurityLog' -Status 'Ok' -WindowStart $T0
        $run = New-AuditRun -RunId ([guid]::NewGuid().ToString()) -StartedAt $T0 -Findings @($f) -Coverage @($c) -Target $Target
        $path = Save-AuditRun -Run $run -Directory $dir
        $back = Import-AuditRun -Path $path
        Assert-Equal 1 @($back.Findings).Count
        Assert-Equal $T0 $back.Findings[0].Timestamp
        Assert-Equal 3 $back.Findings[0].Attributes.LogonType
        Assert-Equal $T0 $back.Coverage[0].WindowStart
        $merged = Merge-AuditRun -Runs @($back, $back)
        Assert-Equal 1 @($merged.Findings).Count 'duplicate events across runs must collapse'
    }
    finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
}

Test-Case 'config file overrides defaults recursively' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('aa-cfg-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        Set-Content -LiteralPath $tmp -Value '{ "_comment": "x", "Collection": { "MaxParallelHosts": 3 }, "Smtp": { "Host": "mail.corp.local" } }' -Encoding UTF8
        $cfg = Get-AuditConfig -Path $tmp
        Assert-Equal 3 $cfg.Collection.MaxParallelHosts
        Assert-Equal 20 $cfg.Collection.ConnectTimeoutSeconds
        Assert-Equal 'mail.corp.local' $cfg.Smtp.Host
        Assert-True (-not $cfg.ContainsKey('_comment'))
        Assert-Equal 'Auto' $cfg.Collection.CompatibilityMode
    }
    finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
}

Test-Case 'shipped example config parses' {
    $cfg = Get-AuditConfig -Path (Join-Path $root 'Config/AdminAudit.config.json')
    Assert-True ($cfg.Authorization.AllowedGroup) 'AllowedGroup missing'
    Assert-True (-not $cfg.Scope.ContainsKey('_comment')) 'nested comment keys must be removed'
}

Test-Case 'invalid compatibility mode is rejected' {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('aa-cfg-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        Set-Content -LiteralPath $tmp -Value '{ "Collection": { "CompatibilityMode": "Fancy" } }' -Encoding UTF8
        $threw = $false
        try { Get-AuditConfig -Path $tmp | Out-Null } catch { $threw = $true }
        Assert-True $threw
    }
    finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
}

Test-Case 'compatibility check: Auto uses detected versions, Legacy assumes 2008 / PS 2.0' {
    $m = @{ Name = 'x'; MinPSVersion = '3.0'; MinOSVersion = '6.2' }
    $h2008 = New-AuditHostInfo -Name 'old' -OperatingSystemVersion '6.0 (6002)'
    $h2019 = New-AuditHostInfo -Name 'new' -OperatingSystemVersion '10.0 (17763)'
    $hUnknown = New-AuditHostInfo -Name 'manual'
    Assert-True ($null -ne (Test-AuditMethodCompatible -Method $m -HostInfo $h2008 -Transport 'Rpc' -Mode Auto)) '2008 must be skipped (OS)'
    Assert-True ($null -eq (Test-AuditMethodCompatible -Method $m -HostInfo $h2019 -Transport 'WinRM' -RemotePSVersion '5.1.17763.1' -Mode Auto))
    Assert-True ($null -ne (Test-AuditMethodCompatible -Method $m -HostInfo $h2019 -Transport 'WinRM' -RemotePSVersion '2.0' -Mode Auto)) 'PS 2.0 endpoint'
    Assert-True ($null -eq (Test-AuditMethodCompatible -Method $m -HostInfo $hUnknown -Transport 'Rpc' -Mode Auto)) 'unknown OS is allowed in Auto'
    Assert-True ($null -ne (Test-AuditMethodCompatible -Method $m -HostInfo $h2019 -Transport 'Rpc' -Mode Legacy)) 'Legacy forces skip'
    Assert-True ($null -eq (Test-AuditMethodCompatible -Method @{ Name = 'y' } -HostInfo $h2008 -Transport 'WinRM' -RemotePSVersion '2.0' -Mode Legacy)) 'plain methods always run'
}

# ============================================================================ Kontozuordnung
Write-Host 'Account matching'

Test-Case 'name variants cover common spellings' {
    $v = @(Get-AuditNameVariant -SamAccountName 'Administrator')
    Assert-True ($v -ccontains 'administrator' -and $v -ccontains 'ADMINISTRATOR' -and $v -ccontains 'Administrator')
    Assert-True (@($Target.KerberosVariants) -ccontains 'Administrator@CORP.LOCAL')
}

Test-Case 'SID match wins and is domain scoped' {
    $m = Resolve-AuditAccountMatch -Target $Target -Sid "$DomainSid-500" -Name 'renamedAdmin'
    Assert-Equal 'Domain' $m.Scope; Assert-Equal 'Sid' $m.Match
}

Test-Case 'local RID 500 is recognised as a different account' {
    $m = Resolve-AuditAccountMatch -Target $Target -Sid 'S-1-5-21-9-9-9-500' -Name 'Administrator' -Domain 'SRV01' -HostShortName 'srv01'
    Assert-Equal 'Local' $m.Scope
    $m = Resolve-AuditAccountMatch -Target $Target -Name 'Administrator' -Domain 'SRV01' -HostShortName 'srv01'
    Assert-Equal 'Local' $m.Scope
    $m = Resolve-AuditAccountMatch -Target $Target -Name '.\administrator' -HostShortName 'srv01'
    Assert-Equal 'Local' $m.Scope
}

Test-Case 'name forms map to the domain account' {
    foreach ($case in @(@('CORP\administrator', ''), @('administrator@CORP.LOCAL', ''), @('Administrator', 'corp.local'), @('ADMINISTRATOR', 'CORP'))) {
        $m = Resolve-AuditAccountMatch -Target $Target -Name $case[0] -Domain $case[1] -HostShortName 'srv01'
        Assert-Equal 'Domain' $m.Scope ($case -join ' / ')
        Assert-Equal 'Name' $m.Match
    }
}

Test-Case 'unqualified name is ambiguous on members, domain on DCs' {
    Assert-Equal 'Ambiguous' (Resolve-AuditAccountMatch -Target $Target -Name 'Administrator' -HostShortName 'srv01').Match
    Assert-Equal 'Domain' (Resolve-AuditAccountMatch -Target $Target -Name 'Administrator' -HostShortName 'dc01' -IsDomainController $true).Scope
}

Test-Case 'other accounts do not match' {
    Assert-True ($null -eq (Resolve-AuditAccountMatch -Target $Target -Sid "$DomainSid-1105" -Name 'Administrator'))
    Assert-True ($null -eq (Resolve-AuditAccountMatch -Target $Target -Name 'CORP\adm-mueller'))
    Assert-True ($null -eq (Resolve-AuditAccountMatch -Target $Target -Sid 'S-1-0-0' -Name ''))
}

Test-Case 'SID to LDAP filter' {
    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { Write-Host '         (SecurityIdentifier needs Windows - skipped)' -ForegroundColor DarkYellow; return }
    $f = ConvertTo-AuditLdapSidFilter -Sid 'S-1-5-32-544'
    Assert-Equal '\01\02\00\00\00\00\00\05\20\00\00\00\20\02\00\00' $f
}

# ============================================================================ Abgleich
Write-Host 'Cross-check'

function New-Item2([int]$Seconds, [hashtable]$Extra = @{}) { $h = @{ Time = $T0.AddSeconds($Seconds) }; foreach ($k in $Extra.Keys) { $h[$k] = $Extra[$k] }; $h }

Test-Case 'timeline: match, only-primary, only-secondary, out of window' {
    $win = @{ Start = $T0.AddHours(-1); End = $T0.AddHours(5) }
    $p = @((New-Item2 0), (New-Item2 3600), (New-Item2 -7200))
    $s = @((New-Item2 30), (New-Item2 7200))
    $r = Compare-AuditTimeline -Primary $p -Secondary $s -PrimaryWindow $win -SecondaryWindow $win -ToleranceSeconds 60
    $states = @($r.Primary | ForEach-Object { $_.State })
    Assert-Equal 'NotChecked,Confirmed,OnlyPrimary' ($states -join ',')
    Assert-Equal 'Confirmed,OnlySecondary' (@($r.Secondary | ForEach-Object { $_.State }) -join ',')
}

Test-Case 'timeline: missing secondary source is Unverifiable, never "nothing found"' {
    $r = Compare-AuditTimeline -Primary @((New-Item2 0)) -Secondary @() -PrimaryWindow @{ Start = $T0; End = $T0 } -SecondaryWindow $null
    Assert-Equal 'Unverifiable' $r.Primary[0].State
}

Test-Case 'timeline: each secondary event is used only once' {
    $win = @{ Start = $T0.AddHours(-1); End = $T0.AddHours(1) }
    $r = Compare-AuditTimeline -Primary @((New-Item2 0), (New-Item2 5)) -Secondary @((New-Item2 2)) -PrimaryWindow $win -SecondaryWindow $win -ToleranceSeconds 60
    Assert-Equal 1 @($r.Primary | Where-Object { $_.State -eq 'Confirmed' }).Count
    Assert-Equal 1 @($r.Primary | Where-Object { $_.State -eq 'OnlyPrimary' }).Count
}

Test-Case 'timeline: CanMatch restricts pairing' {
    $win = @{ Start = $T0.AddHours(-1); End = $T0.AddHours(1) }
    $r = Compare-AuditTimeline -Primary @((New-Item2 0 @{ T = 3 })) -Secondary @((New-Item2 1)) -PrimaryWindow $win -SecondaryWindow $win `
        -NeedsMatch { param($p) $true } -CanMatch { param($p, $s) $p.T -eq 10 }
    Assert-Equal 'OnlyPrimary' $r.Primary[0].State
    Assert-Equal 'OnlySecondary' $r.Secondary[0].State
}

Test-Case 'merge of cross-check states' {
    Assert-Equal 'Confirmed' (Merge-AuditCrossCheckState @('Confirmed', 'Confirmed'))
    Assert-Equal 'Confirmed' (Merge-AuditCrossCheckState @('Confirmed', 'NotChecked'))
    Assert-Equal 'Partial' (Merge-AuditCrossCheckState @('Confirmed', 'OnlyPrimary'))
    Assert-Equal 'Conflict' (Merge-AuditCrossCheckState @('Confirmed', 'Conflict'))
    Assert-Equal 'Unverifiable' (Merge-AuditCrossCheckState @('Unverifiable', 'NotChecked'))
    Assert-Equal 'NotChecked' (Merge-AuditCrossCheckState @())
}

Test-Case 'point in time comparison' {
    $win = @{ Start = $T0; End = $T0.AddDays(2) }
    Assert-Equal 'Confirmed' (Compare-AuditPointInTime -AttributeTime $T0.AddHours(5) -EventTimes @($T0.AddHours(5).AddSeconds(-20)) -EventWindow $win).State
    Assert-Equal 'Conflict' (Compare-AuditPointInTime -AttributeTime $T0.AddHours(1) -EventTimes @($T0.AddHours(5)) -EventWindow $win).State
    Assert-Equal 'OnlySecondary' (Compare-AuditPointInTime -AttributeTime $T0.AddHours(5) -EventTimes @() -EventWindow $win).State
    Assert-Equal 'NotChecked' (Compare-AuditPointInTime -AttributeTime $T0.AddDays(-30) -EventTimes @() -EventWindow $win).State
    Assert-Equal 'Conflict' (Compare-AuditPointInTime -AttributeTime $null -EventTimes @($T0) -EventWindow $win).State
    Assert-Equal 'Confirmed' (Compare-AuditPointInTime -AttributeTime $null -EventTimes @() -EventWindow $win).State
    Assert-Equal 'Unverifiable' (Compare-AuditPointInTime -AttributeTime $T0 -EventTimes @($T0) -EventWindow $null).State
}

Test-Case 'keyed set comparison' {
    $a = @(@{ K = 'a'; User = 'CORP\Administrator' }, @{ K = 'b'; User = 'x' }, @{ K = 'c'; User = 'y' })
    $b = @(@{ K = 'a'; User = 'CORP\Administrator' }, @{ K = 'b'; User = 'z' }, @{ K = 'd'; User = 'y' })
    $r = @(Compare-AuditKeyedSet -Primary $a -Secondary $b -KeySelector { param($i) $i.K } -Fields @('User'))
    $map = @{}; foreach ($x in $r) { $map[$x.Key] = $x.State }
    Assert-Equal 'Confirmed' $map['a']; Assert-Equal 'Conflict' $map['b']; Assert-Equal 'OnlyPrimary' $map['c']; Assert-Equal 'OnlySecondary' $map['d']
    $r = @(Compare-AuditKeyedSet -Primary $a -Secondary @() -KeySelector { param($i) $i.K } -SecondaryAvailable $false)
    Assert-Equal 'Unverifiable' $r[0].State
}

# ============================================================================ Remote-Hilfen
Write-Host 'Remote helpers'

Test-Case 'event parser reads EventData, keywords and time' {
    $e = New-FakeEvent -Id 4624 -Time $T0 -Data @{ TargetUserSid = $Target.Sid; TargetUserName = 'Administrator'; LogonType = '10'; IpAddress = '::ffff:10.0.0.5' }
    $h = ConvertFrom-AuditEventRecord $e
    Assert-Equal 4624 $h.EventId
    Assert-Equal '10' $h.LogonType
    Assert-Equal $Target.Sid $h.TargetUserSid
    Assert-True $h.AuditSuccess
    Assert-Equal $T0 (ConvertFrom-AuditTimeString $h.TimeCreated)
}

Test-Case 'event parser reads UserData (TerminalServices)' {
    $e = New-FakeEvent -Id 21 -Time $T0 -UserData @{ User = 'CORP\Administrator'; SessionID = '2'; Address = '10.0.0.7' } -Provider 'Microsoft-Windows-TerminalServices-LocalSessionManager'
    $h = ConvertFrom-AuditEventRecord $e
    Assert-Equal 'CORP\Administrator' $h.User
    Assert-Equal '10.0.0.7' $h.Address
}

Test-Case 'query list is well-formed XML with escaped XPath' {
    $q = New-AuditQueryList @(@{ Path = 'Security'; Query = "*[EventData[Data[@Name='TargetUserName']='a<b']]" })
    $x = [xml]$q
    Assert-Equal "*[EventData[Data[@Name='TargetUserName']='a<b']]" $x.QueryList.Query.Select.InnerText
    Assert-Equal 'EventID=1 or EventID=2' (New-AuditXPathOr 'EventID' @(1, 2))
    Assert-True ((Get-AuditTimeFilter 2) -like '*172800000*')
    Assert-Equal '' (Get-AuditTimeFilter 0)
}

Test-Case 'error classification' {
    Assert-Equal 'AccessDenied' (Get-AuditErrorKind (New-Object System.UnauthorizedAccessException 'x'))
    Assert-Equal 'AccessDenied' (Get-AuditErrorKind (New-Object System.Exception 'Zugriff verweigert'))
    Assert-Equal 'Unreachable' (Get-AuditErrorKind (New-Object System.Exception 'The RPC server is unavailable'))
    Assert-Equal 'NotSupported' (Get-AuditErrorKind (New-Object System.Exception 'AUDIT_NOTSUPPORTED: x'))
    Assert-Equal 'NoEvents' (Get-AuditErrorKind (New-Object System.Exception 'No events were found that match the specified selection criteria.'))
    Assert-Equal 'Error' (Get-AuditErrorKind (New-Object System.Exception 'something else'))
}

# ============================================================================ Logon-Analyse Ende-zu-Ende
Write-Host 'Logon analysis'

$srv = New-AuditHostInfo -Name 'srv01.corp.local'
$dc1 = New-AuditHostInfo -Name 'dc01.corp.local' -IsDomainController $true
$dc2 = New-AuditHostInfo -Name 'dc02.corp.local' -IsDomainController $true
$win0 = $T0.AddDays(-2)

$tRdp = $T0.AddHours(1)
$secSrv = @(
    (New-Rec -Id 4624 -Time $tRdp -Data @{ TargetUserSid = $Target.Sid; TargetUserName = 'Administrator'; TargetDomainName = 'CORP'; LogonType = '10'; IpAddress = '10.0.0.5'; WorkstationName = 'WS-IT-04'; TargetLogonId = '0x1111'; AuthenticationPackageName = 'Negotiate' })
    (New-Rec -Id 4672 -Time $tRdp -Data @{ SubjectUserSid = $Target.Sid; SubjectUserName = 'Administrator'; SubjectDomainName = 'CORP'; SubjectLogonId = '0x1111' })
    (New-Rec -Id 4624 -Time $T0.AddHours(3) -Data @{ TargetUserSid = $Target.Sid; TargetUserName = 'Administrator'; TargetDomainName = 'CORP'; LogonType = '2'; TargetLogonId = '0x2222' })
    (New-Rec -Id 4624 -Time $T0.AddHours(4) -Data @{ TargetUserSid = $Target.Sid; TargetUserName = 'Administrator'; TargetDomainName = 'CORP'; LogonType = '3'; IpAddress = '10.0.0.9'; TargetLogonId = '0x3' })
    (New-Rec -Id 4624 -Time $T0.AddHours(5) -Data @{ TargetUserSid = $Target.Sid; TargetUserName = 'Administrator'; TargetDomainName = 'CORP'; LogonType = '3'; IpAddress = '10.0.0.9'; TargetLogonId = '0x4' })
    (New-Rec -Id 4624 -Time $T0.AddHours(6) -Data @{ TargetUserSid = $Target.Sid; TargetUserName = 'Administrator'; TargetDomainName = 'CORP'; LogonType = '5'; TargetLogonId = '0x5' })
    (New-Rec -Id 4625 -Time $T0.AddHours(7) -Failure -Data @{ TargetUserSid = 'S-1-0-0'; TargetUserName = 'administrator'; TargetDomainName = 'CORP'; LogonType = '3'; Status = '0xc000006d'; SubStatus = '0xc000006a'; IpAddress = '10.0.0.66' })
    (New-Rec -Id 4625 -Time $T0.AddHours(8) -Failure -Data @{ TargetUserSid = 'S-1-0-0'; TargetUserName = 'Administrator'; TargetDomainName = 'SRV01'; LogonType = '3'; Status = '0xc000006d' })
    (New-Rec -Id 4648 -Time $T0.AddHours(9) -Data @{ SubjectUserSid = "$DomainSid-1105"; SubjectUserName = 'mueller'; SubjectDomainName = 'CORP'; TargetUserName = 'Administrator'; TargetDomainName = 'CORP'; TargetServerName = 'fileserver'; ProcessName = 'C:\Windows\System32\net.exe' })
)
$tsSrv = @(
    (New-Rec -Id 21 -Time $tRdp.AddSeconds(2) -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -UserData @{ User = 'CORP\Administrator'; SessionID = '2'; Address = '10.0.0.5' })
    (New-Rec -Id 1149 -Time $tRdp.AddSeconds(-5) -Log 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -UserData @{ Param1 = 'Administrator'; Param2 = 'CORP'; Param3 = '10.0.0.5' })
    (New-Rec -Id 21 -Time $T0.AddHours(10) -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -UserData @{ User = 'CORP\Administrator'; SessionID = '3'; Address = '10.0.0.8' })
    (New-Rec -Id 24 -Time $T0.AddHours(11) -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -UserData @{ User = 'CORP\Administrator'; SessionID = '3'; Address = '10.0.0.8' })
)
foreach ($r in $tsSrv) {
    if ($r.ContainsKey('Param1')) { $r['AuditUserName'] = $r.Param1; $r['AuditUserDomain'] = $r.Param2 }
    else { $r['AuditUserDomain'] = $r.User.Split('\')[0]; $r['AuditUserName'] = $r.User.Split('\')[1] }
}
$wlSrv = @(
    (New-Rec -Id 7001 -Time $tRdp.AddSeconds(1) -Log 'System' -Provider 'Microsoft-Windows-Winlogon' -Data @{ TSId = '2'; UserSid = $Target.Sid })
)
$profileRec = @{ KeyName = $Target.Sid; IsBak = $false; ProfileImagePath = 'C:\Users\Administrator'; State = 0
                 LoadTime = (ConvertTo-AuditIsoString $tRdp.AddSeconds(3)); UnloadTime = $null; NtUserDatLastWrite = (ConvertTo-AuditIsoString $tRdp) }

$tTgt = $T0.AddHours(2)
$secDc1 = @(
    (New-Rec -Machine 'dc01.corp.local' -Id 4768 -Time $tTgt -Data @{ TargetUserName = 'Administrator'; TargetDomainName = 'CORP'; TargetSid = $Target.Sid; Status = '0x0'; IpAddress = '::ffff:10.0.0.5'; ServiceName = 'krbtgt' })
    (New-Rec -Machine 'dc01.corp.local' -Id 4769 -Time $tTgt.AddSeconds(1) -Data @{ TargetUserName = 'Administrator@CORP.LOCAL'; TargetDomainName = 'CORP.LOCAL'; Status = '0x0'; IpAddress = '::ffff:10.0.0.5'; ServiceName = 'srv01$' })
    (New-Rec -Machine 'dc01.corp.local' -Id 4776 -Time $tTgt.AddMinutes(30) -Failure -Data @{ TargetUserName = 'Administrator'; Workstation = 'OLD-SCANNER'; Status = '0xc000006a' })
    (New-Rec -Machine 'dc01.corp.local' -Id 4724 -Time $T0.AddDays(-1) -Data @{ TargetUserName = 'Administrator'; TargetDomainName = 'CORP'; TargetSid = $Target.Sid })
)
function New-AdRecord([string]$Dc, [datetime]$LastLogon, [datetime]$PwdLastSet, [object]$BadPwd) {
    @{ DomainController = $Dc; lastLogon = [string]$LastLogon.ToFileTimeUtc(); logonCount = '42'; badPwdCount = '1'
       badPasswordTime = $(if ($BadPwd) { [string]([datetime]$BadPwd).ToFileTimeUtc() } else { '0' })
       lastLogonTimestamp = [string]$T0.AddDays(-3).ToFileTimeUtc(); pwdLastSet = [string]$PwdLastSet.ToFileTimeUtc()
       whenChanged = (ConvertTo-AuditIsoString $T0); whenCreated = (ConvertTo-AuditIsoString $T0.AddYears(-20)); userAccountControl = '66048'
       adminCount = '1'; servicePrincipalName = @('MSSQLSvc/sql01.corp.local:1433'); PwdLastSetVersion = '7'; PwdLastSetOriginatingDsa = 'CN=NTDS Settings,CN=DC01'
       LogonTimeSyncIntervalDays = $null }
}
$pwd = $T0.AddDays(-1)

$results = @(
    (New-FakeMethodResult -HostName $srv.Name -Method 'SecurityLog' -Role 'Primary' -Records $secSrv -WindowStart $win0 -HostInfo $srv)
    (New-FakeMethodResult -HostName $srv.Name -Method 'TerminalServicesLog' -Records $tsSrv -WindowStart $win0 -HostInfo $srv)
    (New-FakeMethodResult -HostName $srv.Name -Method 'WinlogonSystemLog' -Records $wlSrv -WindowStart $win0 -HostInfo $srv)
    (New-FakeMethodResult -HostName $srv.Name -Method 'ProfileList' -Records @($profileRec) -HostInfo $srv -Transport 'Rpc')
    (New-FakeMethodResult -HostName $dc1.Name -Method 'SecurityLog' -Role 'Primary' -Records $secDc1 -WindowStart $win0 -HostInfo $dc1)
    (New-FakeMethodResult -HostName $dc1.Name -Method 'TerminalServicesLog' -Status 'NotSupported' -HostInfo $dc1)
    (New-FakeMethodResult -HostName $dc1.Name -Method 'WinlogonSystemLog' -Records @() -WindowStart $win0 -HostInfo $dc1)
    (New-FakeMethodResult -HostName $dc1.Name -Method 'ProfileList' -Records @() -HostInfo $dc1)
    (New-FakeMethodResult -HostName $dc1.Name -Method 'ADAttributes' -Records @((New-AdRecord 'dc01.corp.local' $tTgt.AddSeconds(20) $pwd $T0.AddHours(12))) -HostInfo $dc1 -Transport 'Ldap')
    (New-FakeMethodResult -HostName $dc2.Name -Method 'SecurityLog' -Role 'Primary' -Status 'Unreachable' -HostInfo $dc2)
    (New-FakeMethodResult -HostName $dc2.Name -Method 'ADAttributes' -Records @((New-AdRecord 'dc02.corp.local' $T0.AddDays(-5) $pwd.AddSeconds(1) $null)) -HostInfo $dc2 -Transport 'Ldap')
)
$collector = Get-AuditCollector -Name 'Logon'
Set-AuditLanguage 'de-DE'
$findings = @(& $collector.Analyze $Context $results $Target @{ IncludeLocalAdministrator = $false; CrossCheckToleranceSeconds = 120 } @($srv, $dc1, $dc2))

function Find-One([scriptblock]$Where, [string]$What) {
    $m = @($findings | Where-Object $Where)
    if ($m.Count -ne 1) { throw "expected exactly one finding for '$What', got $($m.Count)" }
    $m[0]
}

Test-Case 'all findings satisfy the schema' {
    Assert-True ($findings.Count -gt 5) "only $($findings.Count) findings"
    foreach ($f in $findings) { $e = Test-AuditFinding $f; Assert-Equal 0 $e.Count "$($f.DetailKey): $($e -join '; ')" }
}

Test-Case 'RDP logon confirmed by LSM, RCM and Winlogon; 4672 folded in' {
    $f = Find-One { $_.Host -eq $srv.Name -and $_.Attributes.EventId -eq 4624 -and $_.Attributes.LogonType -eq 10 } 'RDP 4624'
    Assert-Equal 'Confirmed' $f.CrossCheck
    Assert-Equal 'High' $f.Confidence
    Assert-True $f.Attributes.Privileged 'privileged flag'
    Assert-Equal 0 @($findings | Where-Object { $_.Attributes.EventId -eq 4672 }).Count '4672 must be merged'
    Assert-True (@($f.Evidence | Where-Object { $_.Role -eq 'CrossCheck' }).Count -ge 3) 'cross-check evidence'
    Assert-Equal 'SecurityLog (WinRM)' $f.Method
}

Test-Case 'console logon without any secondary trace is OnlyPrimary' {
    $f = Find-One { $_.Host -eq $srv.Name -and $_.Attributes.LogonType -eq 2 } 'type 2'
    Assert-Equal 'OnlyPrimary' $f.CrossCheck
    Assert-True (Test-AuditDiscrepancy $f)
}

Test-Case 'network logons are aggregated and marked as not checkable' {
    $f = Find-One { $_.Host -eq $srv.Name -and $_.Attributes.EventId -eq 4624 -and $_.Attributes.LogonType -eq 3 } 'type 3'
    Assert-Equal 2 $f.Attributes.Count
    Assert-Equal 'NotChecked' $f.CrossCheck
    Assert-Equal ($T0.AddHours(5)) $f.Timestamp
    Assert-Equal 2 @($f.Attributes.RecordIds).Count
}

Test-Case 'service logon (type 5) is reported' {
    [void](Find-One { $_.Attributes.LogonType -eq 5 } 'type 5')
}

Test-Case 'failed logon by name is matched to the domain account; local one is ignored' {
    $f = Find-One { $_.Attributes.EventId -eq 4625 } '4625'
    Assert-Equal 'Domain' $f.AccountScope
    Assert-Equal 'Name' $f.AccountMatch
    Assert-Equal '10.0.0.66' $f.Attributes.SourceIp
}

Test-Case 'explicit use of the credentials by another user (4648)' {
    $f = Find-One { $_.Attributes.EventId -eq 4648 } '4648'
    Assert-Equal 'CredentialsUsed' $f.Attributes.Role
    Assert-Equal 'fileserver' $f.Attributes.TargetServer
}

Test-Case 'RDP session without 4624 is OnlySecondary' {
    $f = Find-One { $_.ObjectType -eq 'SessionEvent' -and $_.Attributes.EventId -eq 21 } 'LSM 21 leftover'
    Assert-Equal 'OnlySecondary' $f.CrossCheck
    Assert-Equal '10.0.0.8' $f.Attributes.SourceIp
}

Test-Case 'disconnect events are kept as context' {
    $f = Find-One { $_.ObjectType -eq 'SessionEvent' -and $_.Attributes.EventId -eq 24 } 'LSM 24'
    Assert-Equal 'NotChecked' $f.CrossCheck
}

Test-Case 'profile load time confirmed by logon event' {
    $f = Find-One { $_.ObjectType -eq 'UserProfile' -and $_.Host -eq $srv.Name } 'profile'
    Assert-Equal 'Confirmed' $f.CrossCheck
    Assert-Equal 'C:\Users\Administrator' $f.Attributes.ProfileImagePath
}

Test-Case 'DC events: TGT, TGS and NTLM failure' {
    $tgt = Find-One { $_.Host -eq $dc1.Name -and $_.Attributes.EventId -eq 4768 } '4768'
    Assert-Equal '10.0.0.5' $tgt.Attributes.SourceIp
    Assert-Equal 'Sid' $tgt.AccountMatch
    $tgs = Find-One { $_.Host -eq $dc1.Name -and $_.Attributes.EventId -eq 4769 } '4769'
    Assert-Equal 'srv01$' $tgs.Attributes.ServiceName
    Assert-Equal 'Domain' $tgs.AccountScope
    $ntlm = Find-One { $_.Host -eq $dc1.Name -and $_.Attributes.EventId -eq 4776 } '4776'
    Assert-Equal 'OLD-SCANNER' $ntlm.Attributes.Workstation
    Assert-True (-not $ntlm.Attributes.Success)
}

Test-Case 'lastLogon on dc01 confirmed by 4768' {
    $f = Find-One { $_.Host -eq $dc1.Name -and $_.Attributes.Attribute -eq 'lastLogon' } 'lastLogon dc01'
    Assert-Equal 'Confirmed' $f.CrossCheck
    Assert-Equal 'High' $f.Confidence
}

Test-Case 'badPasswordTime without failure event at that time is flagged' {
    $f = Find-One { $_.Host -eq $dc1.Name -and $_.Attributes.Attribute -eq 'badPasswordTime' } 'badPasswordTime dc01'
    Assert-Equal 'OnlySecondary' $f.CrossCheck
}

Test-Case 'dc02 with unreachable security log: AD attribute is Unverifiable, not "no logons"' {
    $f = Find-One { $_.Host -eq $dc2.Name -and $_.Attributes.Attribute -eq 'lastLogon' } 'lastLogon dc02'
    Assert-Equal 'Unverifiable' $f.CrossCheck
}

Test-Case 'pwdLastSet differing between DCs is a conflict' {
    $f = Find-One { $_.Attributes.Attribute -eq 'pwdLastSet' } 'pwdLastSet'
    Assert-Equal 'Conflict' $f.CrossCheck
    Assert-Equal 'Low' $f.Confidence
    Assert-True ($f.CrossCheckNote -like '*dc01*dc02*' -or $f.CrossCheckNote -like '*dc02*dc01*') $f.CrossCheckNote
}

Test-Case 'account state lists SPNs and is authoritative' {
    $f = Find-One { $_.ObjectType -eq 'ADAccount' } 'account'
    Assert-Equal 1 @($f.Attributes.ServicePrincipalNames).Count
    Assert-Equal 'High' $f.Confidence
    Assert-True (@($f.Attributes.Flags) -contains 'DONT_EXPIRE_PASSWORD')
}

Test-Case 'local administrator is reported only when enabled' {
    $withLocal = @(& $collector.Analyze $Context $results $Target @{ IncludeLocalAdministrator = $true } @($srv, $dc1, $dc2))
    $local = @($withLocal | Where-Object { $_.AccountScope -eq 'Local' })
    Assert-Equal 1 $local.Count
    Assert-Equal 'SRV01\Administrator' $local[0].Account
}

# ============================================================================ Runner
if (-not $SkipRunner) {
    Write-Host 'Runner'

    $tmpCollectors = Join-Path ([System.IO.Path]::GetTempPath()) ('aa-coll-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $tmpCollectors)
    Set-Content -LiteralPath (Join-Path $tmpCollectors 'Probe.Collector.ps1') -Encoding ASCII -Value @'
@{
    Name = 'Probe'; Version = '0.0.1'
    Methods = @(
        @{ Name = 'Fast'; Role = 'Primary'; Scope = 'Host'; Transports = @('Rpc'); Script = {
            param($ComputerName, $Target, $Options)
            $r = New-AuditRemoteResult; [void]$r.Records.Add(@{ Seen = $ComputerName; Sid = $Target.Sid }); $r } }
        @{ Name = 'Fallback'; Role = 'CrossCheck'; Scope = 'Host'; Transports = @('WinRM', 'Rpc'); Script = {
            param($ComputerName, $Target, $Options)
            $r = New-AuditRemoteResult; [void]$r.Records.Add(@{ Via = $ComputerName }); $r } }
        @{ Name = 'Denied'; Role = 'CrossCheck'; Scope = 'Host'; Transports = @('Rpc'); Script = {
            param($ComputerName, $Target, $Options) throw (New-Object System.UnauthorizedAccessException 'Access is denied') } }
        @{ Name = 'Slow'; Role = 'CrossCheck'; Scope = 'Host'; Transports = @('Rpc'); Script = {
            param($ComputerName, $Target, $Options) if ($Options.IsDomainController) { Start-Sleep -Seconds 60 }; New-AuditRemoteResult } }
        @{ Name = 'NeedsNewOs'; Role = 'CrossCheck'; Scope = 'Host'; Transports = @('Rpc'); MinOSVersion = '6.2'; Script = {
            param($ComputerName, $Target, $Options) New-AuditRemoteResult } }
        @{ Name = 'DcOnly'; Role = 'CrossCheck'; Scope = 'DomainController'; Transports = @('Ldap'); Script = {
            param($ComputerName, $Target, $Options) New-AuditRemoteResult } }
    )
    Analyze = { param($Context, $MethodResults, $Target, $Options, $Hosts) @() }
}
'@
    $cfg = Get-AuditDefaultConfig
    $cfg.Collection.CollectorPath = $tmpCollectors
    $cfg.Collection.HostTimeoutSeconds = 4
    $cfg.Collection.ConnectTimeoutSeconds = 2
    $cfg.Collection.MaxParallelHosts = 4
    $hosts = @(
        (New-AuditHostInfo -Name 'localhost' -OperatingSystemVersion '6.0 (6002)')
        (New-AuditHostInfo -Name '127.0.0.1' -IsDomainController $true)   # der "DC" haengt in Methode Slow
        (New-AuditHostInfo -Name 'does-not-exist.invalid')
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = [hashtable]::Synchronized(@{})
    $mr = @(Invoke-AuditCollection -Config $cfg -Target $Target -Hosts $hosts -CollectorNames @('Probe') -Status $status)
    $sw.Stop()
    function Get-R([string]$h, [string]$m) { $mr | Where-Object { $_.Host -eq $h -and $_.Method -eq $m } | Select-Object -First 1 }

    Test-Case 'runner: every planned method has exactly one result' {
        # localhost 5 Host-Methoden, DC 6, nicht aufloesbarer Host 5
        Assert-Equal 16 $mr.Count ("got: " + (($mr | ForEach-Object { $_.Host + '/' + $_.Method + '=' + $_.Status }) -join ', '))
        Assert-Equal 3 $status.HostsDone
    }
    Test-Case 'runner: local RPC method returns records with target passed through' {
        $r = Get-R 'localhost' 'Fast'
        Assert-Equal 'Ok' $r.Status $r.Message
        Assert-Equal $Target.Sid @($r.Result.Records)[0].Sid
        Assert-Equal 'localhost' @($r.Result.Records)[0].Seen
    }
    Test-Case 'runner: WinRM failure falls back to RPC and is documented' {
        $r = Get-R 'localhost' 'Fallback'
        Assert-Equal 'Ok' $r.Status $r.Message
        Assert-Equal 'Rpc' $r.Transport
        Assert-True (@($r.TransportNotes | Where-Object { $_ -like 'WinRM*' }).Count -ge 1) 'WinRM note missing'
    }
    Test-Case 'runner: method above the host OS level is Skipped, not empty' {
        $r = Get-R 'localhost' 'NeedsNewOs'
        Assert-Equal 'Skipped' $r.Status $r.Message
        Assert-True ($r.Message -like '*6.2*') $r.Message
    }
    Test-Case 'runner: access denied is encapsulated as status' {
        Assert-Equal 'AccessDenied' (Get-R 'localhost' 'Denied').Status
    }
    Test-Case 'runner: unresolvable host is Unreachable for host methods' {
        $r = Get-R 'does-not-exist.invalid' 'Fast'
        Assert-Equal 'Unreachable' $r.Status
        Assert-True ($r.Message -like 'DNS*') $r.Message
    }
    Test-Case 'runner: host timeout keeps finished methods and marks the rest' {
        $dcName = $hosts[1].Name
        $slow = Get-R $dcName 'Slow'
        Assert-Equal 'Timeout' $slow.Status $slow.Message
        Assert-Equal 'Ok' (Get-R $dcName 'Fast').Status
        Assert-Equal 'Timeout' (Get-R $dcName 'DcOnly').Status
        Assert-True ($sw.Elapsed.TotalSeconds -lt 40) "run took $($sw.Elapsed.TotalSeconds)s"
        Assert-Equal 'Ok' (Get-R 'localhost' 'Slow').Status
    }
    Test-Case 'runner: coverage records exist for every method result' {
        $cov = @(ConvertTo-AuditCoverage -RunId 'r' -MethodResults $mr -CollectedBy 'me')
        Assert-Equal $mr.Count $cov.Count
        Assert-True (@($cov | Where-Object { $_.Status -eq 'Ok' -and $_.Method -eq 'Fast' -and $_.Host -eq 'localhost' -and $_.ResultCount -eq 1 }).Count -eq 1)
        $fb = $cov | Where-Object { $_.Method -eq 'Fallback' -and $_.Host -eq 'localhost' }
        Assert-True ($fb.Message -like '*WinRM*') $fb.Message
    }
    Remove-Item -LiteralPath $tmpCollectors -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================================ Ergebnis
Write-Host ''
Write-Host ("Passed: {0}  Failed: {1}" -f $script:Passed, $script:Failed) -ForegroundColor $(if ($script:Failed) { 'Red' } else { 'Green' })
if ($script:Failed -gt 0) {
    $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
exit 0
