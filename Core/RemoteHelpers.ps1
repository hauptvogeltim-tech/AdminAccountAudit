# Hilfsfunktionen, die zusammen mit jedem Methoden-Skript auf dem Zielhost laufen.
#
# !!! PowerShell-2.0-kompatibel halten (Server 2008 / 2008 R2) !!!
#   - kein [pscustomobject], kein [ordered], kein ::new(), kein -in/-notin
#   - kein Get-CimInstance, kein ConvertTo-Json, kein -ErrorAction Ignore, kein Get-Content -Raw
#   - .Count nur auf mit @() erzwungenen Arrays
#   - Zeitpunkte als ISO-String ("o") zurueckgeben, nie als DateTime (Serialisierung/Zeitzonen)
# tests/Test-AdminAudit.ps1 prueft diese Regeln statisch.
#
# Die Datei wird im Modul dot-sourced (fuer lokale Ausfuehrung und Tests) und zusaetzlich
# als Text vor jedes Remote-Skript gesetzt.

function New-AuditRemoteResult {
    $r = New-Object PSObject
    $r | Add-Member -MemberType NoteProperty -Name Records -Value (New-Object System.Collections.ArrayList)
    $r | Add-Member -MemberType NoteProperty -Name WindowStart -Value $null
    $r | Add-Member -MemberType NoteProperty -Name WindowEnd -Value $null
    $r | Add-Member -MemberType NoteProperty -Name Truncated -Value $false
    $r | Add-Member -MemberType NoteProperty -Name Preconditions -Value @{}
    $r | Add-Member -MemberType NoteProperty -Name Notes -Value (New-Object System.Collections.ArrayList)
    $r | Add-Member -MemberType NoteProperty -Name Executor -Value ([System.Environment]::MachineName)
    $r | Add-Member -MemberType NoteProperty -Name PSVersion -Value ($PSVersionTable.PSVersion.ToString())
    $r
}

function ConvertTo-AuditRemoteIso {
    param($Value)
    if ($null -eq $Value) { return $null }
    $dt = [datetime]$Value
    if ($dt.Kind -eq [System.DateTimeKind]::Unspecified) { $dt = [System.DateTime]::SpecifyKind($dt, [System.DateTimeKind]::Local) }
    return $dt.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-AuditEventRecord {
    <#
      EventLogRecord -> flache Hashtable. Sprachunabhaengig ueber ToXml():
      System-Felder + EventData (Data Name=...) + UserData (Kindelemente des ersten Elements).
      Unbenannte Data-Elemente werden als Data0, Data1, ... abgelegt.
    #>
    param($Event)
    $h = @{}
    $h['EventId'] = [int]$Event.Id
    $h['RecordId'] = [int64]$Event.RecordId
    $h['TimeCreated'] = ConvertTo-AuditRemoteIso $Event.TimeCreated
    $h['Computer'] = [string]$Event.MachineName
    $h['Provider'] = [string]$Event.ProviderName
    $h['LogName'] = [string]$Event.LogName
    $kw = [int64]0
    if ($null -ne $Event.Keywords) { $kw = [int64]$Event.Keywords }
    $h['Keywords'] = $kw
    # Audit-Success-Bit 0x0020000000000000 / Audit-Failure-Bit 0x0010000000000000
    $h['AuditSuccess'] = (($kw -band 0x0020000000000000) -ne 0)
    $h['AuditFailure'] = (($kw -band 0x0010000000000000) -ne 0)
    # System/Security@UserID - eigener Schluessel, damit EventData-Felder ihn nicht ueberschreiben
    $h['SystemUserSid'] = $null
    if ($null -ne $Event.UserId) { $h['SystemUserSid'] = [string]$Event.UserId.Value }

    $xml = [xml]$Event.ToXml()
    $root = $xml.DocumentElement
    $i = 0
    foreach ($node in @($root.ChildNodes)) {
        if ($null -eq $node) { continue }
        if ($node.LocalName -eq 'EventData') {
            foreach ($d in @($node.ChildNodes)) {
                if ($null -eq $d -or $d.LocalName -ne 'Data') { continue }
                $name = $d.GetAttribute('Name')
                if (-not $name) { $name = 'Data' + $i; $i++ }
                $h[$name] = [string]$d.InnerText
            }
        }
        elseif ($node.LocalName -eq 'UserData') {
            foreach ($wrapper in @($node.ChildNodes)) {
                if ($null -eq $wrapper -or $wrapper.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                foreach ($d in @($wrapper.ChildNodes)) {
                    if ($null -eq $d -or $d.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                    $h[$d.LocalName] = [string]$d.InnerText
                }
            }
        }
    }
    return $h
}

function Get-AuditErrorKind {
    # Grobe, sprachunabhaengige Einordnung eines Fehlers (HResult/Typ vor Meldungstext).
    param($ErrorRecord)
    $ex = $ErrorRecord
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        if ($ErrorRecord.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return 'NoEvents' }
        $ex = $ErrorRecord.Exception
    }
    $texts = ''
    while ($null -ne $ex) {
        $typeName = $ex.GetType().FullName
        $hr = 0
        try { $hr = [int]$ex.HResult } catch { $hr = 0 }
        if ($typeName -eq 'System.UnauthorizedAccessException' -or $hr -eq -2147024891) { return 'AccessDenied' }
        if ($typeName -eq 'System.Diagnostics.Eventing.Reader.EventLogNotFoundException') { return 'NotSupported' }
        if ($hr -eq -2147023174 -or $hr -eq -2147023169 -or $hr -eq -2147024843) { return 'Unreachable' }
        $texts = $texts + ' ' + [string]$ex.Message
        $ex = $ex.InnerException
    }
    if ($texts -match 'AUDIT_NOTSUPPORTED') { return 'NotSupported' }
    if ($texts -match 'Access is denied|Zugriff verweigert|Zugriff wurde verweigert') { return 'AccessDenied' }
    if ($texts -match 'No events were found|Es wurden keine Ereignisse gefunden') { return 'NoEvents' }
    if ($texts -match 'There is not an event log|Es ist kein Ereignisprotokoll|does not exist|ist nicht vorhanden|channel.*not found') { return 'NotSupported' }
    if ($texts -match 'RPC server is unavailable|RPC-Server ist nicht verf|network path was not found|Netzwerkpfad wurde nicht gefunden|WinRM|cannot connect') { return 'Unreachable' }
    return 'Error'
}

function Invoke-AuditWinEvent {
    <#
      Get-WinEvent mit FilterXml, lokal (ComputerName leer) oder per RPC.
      "Keine Ereignisse" ist kein Fehler, sondern ein leeres Ergebnis.
      Rueckgabe: Hashtable-Liste (ConvertFrom-AuditEventRecord).
    #>
    param([string]$ComputerName, [string]$FilterXml, [int]$MaxEvents = 0)
    $p = @{ FilterXml = $FilterXml; ErrorAction = 'Stop' }
    if ($ComputerName) { $p['ComputerName'] = $ComputerName }
    if ($MaxEvents -gt 0) { $p['MaxEvents'] = $MaxEvents }
    $out = New-Object System.Collections.ArrayList
    try {
        foreach ($e in (Get-WinEvent @p)) { [void]$out.Add((ConvertFrom-AuditEventRecord $e)) }
    }
    catch {
        if ((Get-AuditErrorKind $_) -ne 'NoEvents') { throw }
    }
    return ,$out
}

function Get-AuditLogInfo {
    <#
      Zeitfenster und Zustand eines Logs: aeltestes Ereignis, Groesse, Modus.
      Grundlage fuer die Coverage-Aussage "in diesem Zeitraum geprueft".
    #>
    param([string]$ComputerName, [string]$LogName)
    $p = @{ ListLog = $LogName; ErrorAction = 'Stop' }
    if ($ComputerName) { $p['ComputerName'] = $ComputerName }
    $log = Get-WinEvent @p
    $info = @{
        LogName      = $LogName
        IsEnabled    = [bool]$log.IsEnabled
        RecordCount  = $log.RecordCount
        FileSize     = $log.FileSize
        MaximumSize  = $log.MaximumSizeInBytes
        LogMode      = [string]$log.LogMode
        Oldest       = $null
        Newest       = $null
    }
    $q = @{ LogName = $LogName; MaxEvents = 1; ErrorAction = 'Stop' }
    if ($ComputerName) { $q['ComputerName'] = $ComputerName }
    try { $o = Get-WinEvent @q -Oldest; if ($o) { $info.Oldest = ConvertTo-AuditRemoteIso $o.TimeCreated } }
    catch { if ((Get-AuditErrorKind $_) -ne 'NoEvents') { throw } }
    try { $n = Get-WinEvent @q; if ($n) { $info.Newest = ConvertTo-AuditRemoteIso $n.TimeCreated } }
    catch { if ((Get-AuditErrorKind $_) -ne 'NoEvents') { throw } }
    return $info
}

function New-AuditXPathOr {
    # ('EventID', 4624, 4625) -> "EventID=4624 or EventID=4625"
    param([string]$Name, $Values)
    $parts = @()
    foreach ($v in @($Values)) { $parts += ($Name + '=' + $v) }
    return ($parts -join ' or ')
}

function ConvertTo-AuditXmlLiteral {
    param([string]$Value)
    return [System.Security.SecurityElement]::Escape($Value)
}

function New-AuditQueryList {
    # Selects: Liste von @{ Path = 'Security'; Query = '*[...]' }
    param($Selects)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<QueryList><Query Id="0">')
    foreach ($s in @($Selects)) {
        [void]$sb.Append('<Select Path="' + (ConvertTo-AuditXmlLiteral $s.Path) + '">' + (ConvertTo-AuditXmlLiteral $s.Query) + '</Select>')
    }
    [void]$sb.Append('</Query></QueryList>')
    return $sb.ToString()
}

function Get-AuditTimeFilter {
    # Zusatzbedingung fuer System[...] bei begrenztem Rueckblick.
    param([int]$LookbackDays)
    if ($LookbackDays -le 0) { return '' }
    $ms = [int64]$LookbackDays * 86400000
    return (' and TimeCreated[timediff(@SystemTime) <= ' + $ms + ']')
}
