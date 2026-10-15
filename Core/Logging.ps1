# Diagnose-Log mit einstellbarem Detailgrad.
#
# Getrennt vom Audit-Log (AuditLog.ps1):
#   Audit-Log   : wer hat wann was abgefragt - immer an, nicht abschaltbar
#   Diagnose-Log: was tut das Tool intern (Verbindungen, Fallbacks, Dauer, Abfragen) - Level einstellbar
#
# Level (aufsteigend gespraechig): Off < Error < Warning < Info < Verbose < Debug
#   Datei und Konsole haben je eine eigene Schwelle (Logging.Level / Logging.ConsoleLevel).
#   Debug enthaelt u. a. die vollstaendigen XPath-Abfragen und Stacktraces.
#
# Mehrere Runspaces (Host-Jobs) schreiben in dieselbe Datei: Zugriff wird ueber eine
# prozessweite Sperre serialisiert. Remote-Skripte sammeln ihre Meldungen im Ergebnis
# (Write-AuditRemoteLog), der Runner traegt sie mit Host und Methode hier ein.
# Meldungstexte sind englisch (grep-bar, unabhaengig von der UI-Sprache).

$script:AuditLogLevels = @{ Off = 0; Error = 1; Warning = 2; Info = 3; Verbose = 4; Debug = 5 }
$script:AuditLogLevelNames = @('Off', 'Error', 'Warning', 'Info', 'Verbose', 'Debug')
$script:AuditDiag = @{
    Level         = 3
    ConsoleLevel  = 2
    Directory     = $null
    Format        = 'Text'
    MaxBytes      = 20MB
    RetentionDays = 30
    RunId         = ''
    Sink          = $null
    SinkLevel     = 3
    WriteFailed   = $false
}
$script:AuditLogLockName = [string]::Intern('AdminAccountAudit.DiagnosticLog.Lock')
$script:AuditSensitiveKeyPattern = 'password|passwort|secret|credential|kennwort|token'

function Get-AuditLogLevelRank {
    param([Parameter(Mandatory)][string]$Level)
    if (-not $script:AuditLogLevels.ContainsKey($Level)) {
        throw "Unknown log level '$Level'. Valid: $($script:AuditLogLevelNames -join ', ')"
    }
    $script:AuditLogLevels[$Level]
}

function Initialize-AuditLogging {
    <#
      Settings: Abschnitt Logging aus der Konfiguration.
      NoMaintenance: keine Aufbewahrungs-Bereinigung (fuer Host-Job-Runspaces).
      Settings.Sink: optionale ConcurrentQueue, die Eintraege zusaetzlich erhaelt (GUI-Logfenster,
                     Konsole der CLI). Settings.SinkLevel = eigene Schwelle dafuer (Standard: Level).
                     Beides wird nicht gespeichert und gilt auch in den Host-Job-Runspaces.
    #>
    param([hashtable]$Settings = @{}, [string]$RunId = '', [switch]$NoMaintenance)
    $s = $script:AuditDiag
    $s.Level = Get-AuditLogLevelRank ([string](Get-AuditProperty $Settings 'Level' 'Info'))
    $s.ConsoleLevel = Get-AuditLogLevelRank ([string](Get-AuditProperty $Settings 'ConsoleLevel' 'Warning'))
    $s.Format = [string](Get-AuditProperty $Settings 'Format' 'Text')
    if (@('Text', 'Json') -notcontains $s.Format) { throw "Logging.Format must be 'Text' or 'Json'" }
    $s.MaxBytes = [int64]([double](Get-AuditProperty $Settings 'MaxFileSizeMB' 20) * 1MB)
    $s.RetentionDays = [int](Get-AuditProperty $Settings 'RetentionDays' 30)
    $s.Sink = Get-AuditProperty $Settings 'Sink'
    $s.SinkLevel = Get-AuditLogLevelRank ([string](Get-AuditProperty $Settings 'SinkLevel' $script:AuditLogLevelNames[$s.Level]))
    $s.RunId = $RunId
    $s.WriteFailed = $false
    $s.Directory = $null

    $dir = Expand-AuditPath ([string](Get-AuditProperty $Settings 'Directory' ''))
    if ($dir -and $s.Level -gt 0) {
        try {
            if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
            $s.Directory = $dir
        }
        catch { Write-Warning "Diagnostic log directory not usable ($dir): $($_.Exception.Message)" }
    }
    if ($s.Directory -and -not $NoMaintenance -and $s.RetentionDays -gt 0) {
        $limit = (Get-Date).AddDays(-$s.RetentionDays)
        foreach ($f in @(Get-ChildItem -LiteralPath $s.Directory -Filter 'diag-*.log' -ErrorAction SilentlyContinue)) {
            if ($f.LastWriteTime -lt $limit) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
        }
    }
}

function Set-AuditLogContext {
    param([string]$RunId = '')
    $script:AuditDiag.RunId = $RunId
}

function Set-AuditLogLevel {
    # Zur Laufzeit umstellen (z. B. GUI-Auswahl). -Console stellt die Konsolenschwelle um.
    param([Parameter(Mandatory)][ValidateSet('Off', 'Error', 'Warning', 'Info', 'Verbose', 'Debug')][string]$Level, [switch]$Console)
    if ($Console) { $script:AuditDiag.ConsoleLevel = Get-AuditLogLevelRank $Level }
    else { $script:AuditDiag.Level = Get-AuditLogLevelRank $Level }
}

function Get-AuditLogLevel {
    [pscustomobject]@{
        Level        = $script:AuditLogLevelNames[$script:AuditDiag.Level]
        ConsoleLevel = $script:AuditLogLevelNames[$script:AuditDiag.ConsoleLevel]
        Directory    = $script:AuditDiag.Directory
        Format       = $script:AuditDiag.Format
        File         = $(if ($script:AuditDiag.Directory) { Get-AuditLogFile } else { $null })
    }
}

function Get-AuditEffectiveLogLevel {
    # Gespraechigste aktive Schwelle - bestimmt, was Remote-Skripte ueberhaupt sammeln.
    $rank = $script:AuditDiag.ConsoleLevel
    if ($script:AuditDiag.Directory -and $script:AuditDiag.Level -gt $rank) { $rank = $script:AuditDiag.Level }
    if ($null -ne $script:AuditDiag.Sink -and $script:AuditDiag.SinkLevel -gt $rank) { $rank = $script:AuditDiag.SinkLevel }
    $script:AuditLogLevelNames[$rank]
}

function Test-AuditLogLevel {
    # Vorab pruefen, ob sich teure Meldungen (z. B. Debug-Dumps) ueberhaupt lohnen.
    param([Parameter(Mandatory)][string]$Level)
    (Get-AuditLogLevelRank $Level) -le (Get-AuditLogLevelRank (Get-AuditEffectiveLogLevel))
}

function Get-AuditLogFile {
    # Eine Datei pro Tag; ueberschreitet sie MaxFileSizeMB, geht es in diag-<Tag>-1.log usw. weiter.
    $day = (Get-Date).ToString('yyyyMMdd')
    $n = 0
    while ($true) {
        $name = if ($n -eq 0) { "diag-$day.log" } else { "diag-$day-$n.log" }
        $path = Join-Path $script:AuditDiag.Directory $name
        if (-not (Test-Path -LiteralPath $path)) { return $path }
        if ($script:AuditDiag.MaxBytes -le 0 -or (Get-Item -LiteralPath $path).Length -lt $script:AuditDiag.MaxBytes) { return $path }
        $n++
    }
}

function Protect-AuditLogData {
    # Werte mit sensiblen Schluesselnamen nie ins Log schreiben.
    param([object]$Data)
    if ($null -eq $Data) { return $null }
    if ($Data -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $Data.Keys) {
            if ([string]$k -match $script:AuditSensitiveKeyPattern) { $h[[string]$k] = '***' }
            else { $h[[string]$k] = Protect-AuditLogData $Data[$k] }
        }
        return $h
    }
    if ($Data -is [System.Security.SecureString] -or $Data -is [System.Management.Automation.PSCredential]) { return '***' }
    return $Data
}

function Format-AuditLogLine {
    param([hashtable]$Entry, [string]$Format)
    if ($Format -eq 'Json') {
        return (ConvertTo-Json -InputObject (ConvertTo-AuditSerializable $Entry) -Depth 8 -Compress)
    }
    $run = [string]$Entry.RunId
    if ($run.Length -gt 8) { $run = $run.Substring(0, 8) }
    $line = '{0} | {1,-7} | {2,-20} | {3,-24} | {4,-8} | {5}' -f $Entry.Time, $Entry.Level, $Entry.Component,
        $(if ($Entry.Host) { $Entry.Host } else { '-' }), $(if ($run) { $run } else { '-' }),
        (([string]$Entry.Message) -replace '\r?\n', ' / ')
    if ($Entry.Data -and $Entry.Data.Count -gt 0) {
        $line += ' :: ' + (ConvertTo-Json -InputObject (ConvertTo-AuditSerializable $Entry.Data) -Depth 6 -Compress)
    }
    $line
}

function Write-AuditLog {
    <#
      Level      : Error | Warning | Info | Verbose | Debug
      Component  : Herkunft, z. B. 'Runner', 'Run', 'Logon/SecurityLog'
      HostName   : betroffener Host (falls zutreffend)
      Data       : zusaetzliche strukturierte Werte (sensible Schluessel werden maskiert)
      ErrorRecord: Exception wird mit Typ und Meldung erfasst, bei Debug mit Stacktrace
      Schreibfehler werden einmal als Warnung gemeldet und brechen nie einen Lauf ab.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('Error', 'Warning', 'Info', 'Verbose', 'Debug')][string]$Level,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [string]$Component = 'Core',
        [string]$HostName = '',
        [hashtable]$Data,
        [object]$ErrorRecord,
        [object]$Time
    )
    $s = $script:AuditDiag
    $rank = $script:AuditLogLevels[$Level]
    $toFile = $s.Directory -and $rank -le $s.Level
    # $null-Vergleich noetig: eine leere Warteschlange waere sonst "falsch"
    $toSink = ($null -ne $s.Sink) -and $rank -le $s.SinkLevel
    $toConsole = $rank -le $s.ConsoleLevel
    if (-not ($toFile -or $toSink -or $toConsole)) { return }

    $d = $null
    if ($Data) { $d = Protect-AuditLogData $Data }
    if ($ErrorRecord) {
        if (-not $d) { $d = [ordered]@{} }
        $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
        $d['Exception'] = $ex.GetType().FullName + ': ' + $ex.Message
        if ($s.Level -ge 5 -and $ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.ScriptStackTrace) {
            $d['StackTrace'] = $ErrorRecord.ScriptStackTrace
        }
    }
    $entry = @{
        Time      = $(if ($Time) { ConvertTo-AuditIsoString $Time } else { ConvertTo-AuditIsoString (Get-AuditUtcNow) })
        Level     = $Level
        Component = $Component
        Host      = $HostName
        RunId     = $s.RunId
        Thread    = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        Message   = $Message
        Data      = $d
    }

    if ($toFile) {
        $line = Format-AuditLogLine -Entry $entry -Format $s.Format
        [System.Threading.Monitor]::Enter($script:AuditLogLockName)
        try {
            $fs = New-Object System.IO.FileStream((Get-AuditLogFile), [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            try {
                $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($line + [Environment]::NewLine)
                $fs.Write($bytes, 0, $bytes.Length)
            }
            finally { $fs.Dispose() }
        }
        catch {
            if (-not $s.WriteFailed) { $s.WriteFailed = $true; Write-Warning "Diagnostic log write failed: $($_.Exception.Message)" }
        }
        finally { [System.Threading.Monitor]::Exit($script:AuditLogLockName) }
    }
    if ($toSink) {
        try { $s.Sink.Enqueue([pscustomobject]$entry) } catch { }
    }
    if ($toConsole) {
        $color = switch ($Level) { 'Error' { 'Red' } 'Warning' { 'Yellow' } 'Info' { 'Gray' } 'Verbose' { 'DarkGray' } default { 'DarkCyan' } }
        $prefix = '[' + $Level.ToUpperInvariant() + '] ' + $(if ($HostName) { $HostName + ': ' } else { '' })
        try { Write-Host ($prefix + $Message) -ForegroundColor $color } catch { }
    }
}

function ConvertFrom-AuditLogLine {
    param([string]$Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    if ($Line.TrimStart().StartsWith('{')) {
        try { $o = $Line | ConvertFrom-Json } catch { return $null }
        return [pscustomobject]@{
            Time = ConvertFrom-AuditTimeString $o.Time; Level = [string]$o.Level; Component = [string]$o.Component
            Host = [string]$o.Host; RunId = [string]$o.RunId; Message = [string]$o.Message; Data = ConvertTo-AuditHashtable $o.Data
        }
    }
    $m = [regex]::Match($Line, '^(?<t>\S+) \| (?<l>\w+)\s* \| (?<c>.*?)\s* \| (?<h>\S+)\s* \| (?<r>\S+)\s* \| (?<m>.*)$')
    if (-not $m.Success) { return $null }
    $msg = $m.Groups['m'].Value
    $data = $null
    $idx = $msg.LastIndexOf(' :: {')
    if ($idx -ge 0) {
        try { $data = ConvertTo-AuditHashtable ($msg.Substring($idx + 4) | ConvertFrom-Json); $msg = $msg.Substring(0, $idx) } catch { $data = $null }
    }
    [pscustomobject]@{
        Time      = ConvertFrom-AuditTimeString $m.Groups['t'].Value
        Level     = $m.Groups['l'].Value
        Component = $m.Groups['c'].Value
        Host      = $(if ($m.Groups['h'].Value -eq '-') { '' } else { $m.Groups['h'].Value })
        RunId     = $(if ($m.Groups['r'].Value -eq '-') { '' } else { $m.Groups['r'].Value })
        Message   = $msg
        Data      = $data
    }
}

function Get-AuditLogEntry {
    <#
      Liest und filtert das Diagnose-Log (Text- und JSON-Zeilen gemischt moeglich).
        -Level Warning     : nur Warning und schwerer
        -RunId abcd1234    : Praefix der RunId genuegt
        -HostName srv01    : Teilstring
        -Pattern 'WinRM'   : Regex auf die Meldung
        -Last 50           : nur die letzten N Treffer
    #>
    param(
        [string]$Directory,
        [ValidateSet('Error', 'Warning', 'Info', 'Verbose', 'Debug')][string]$Level = 'Debug',
        [string]$RunId,
        [string]$HostName,
        [string]$Component,
        [string]$Pattern,
        [object]$Since,
        [int]$Last = 0
    )
    if (-not $Directory) { $Directory = $script:AuditDiag.Directory }
    if (-not $Directory -or -not (Test-Path -LiteralPath $Directory)) { return }
    $max = Get-AuditLogLevelRank $Level
    $sinceUtc = if ($Since) { ConvertFrom-AuditTimeString $Since } else { $null }
    $hits = New-Object System.Collections.ArrayList
    $files = @(Get-ChildItem -LiteralPath $Directory -Filter 'diag-*.log' | Sort-Object LastWriteTime, Name)
    foreach ($f in $files) {
        $fs = New-Object System.IO.FileStream($f.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {
                $e = ConvertFrom-AuditLogLine $line
                if (-not $e) { continue }
                if (-not $script:AuditLogLevels.ContainsKey($e.Level) -or $script:AuditLogLevels[$e.Level] -gt $max) { continue }
                if ($RunId -and -not $e.RunId.StartsWith($RunId.Substring(0, [math]::Min(8, $RunId.Length)))) { continue }
                if ($HostName -and $e.Host -notlike "*$HostName*") { continue }
                if ($Component -and $e.Component -notlike "*$Component*") { continue }
                if ($Pattern -and $e.Message -notmatch $Pattern) { continue }
                if ($sinceUtc -and $e.Time -lt $sinceUtc) { continue }
                [void]$hits.Add($e)
            }
        }
        finally { $reader.Dispose() }
    }
    if ($Last -gt 0 -and $hits.Count -gt $Last) { return $hits.GetRange($hits.Count - $Last, $Last).ToArray() }
    $hits.ToArray()
}
