# Ausfuehrung der Kollektor-Methoden ueber viele Hosts.
#
#  - RunspacePool, ein Job pro Host, Timeout pro Host (ab tatsaechlichem Start, nicht ab Warteschlange)
#  - Transport je Methode in deklarierter Reihenfolge: WinRM zuerst, dann RPC/LDAP-Fallback
#  - Jeder Fehler wird gekapselt und als Status am Methodenergebnis abgelegt - ein Host oder eine
#    Methode bricht nie den Gesamtlauf ab
#  - Abgeschlossene Methoden eines Hosts bleiben auch bei Timeout erhalten (geteilter Zustand)

$script:AuditTransports = @('WinRM', 'Rpc', 'Ldap', 'Local')
$script:AuditMethodScopes = @('Host', 'DomainController')

# ----------------------------------------------------------------------------- Kollektor-Registry

function Test-AuditCollectorManifest {
    param([Parameter(Mandatory)][object]$Manifest, [string]$File = '')
    $err = New-Object System.Collections.ArrayList
    if (-not ($Manifest -is [hashtable])) { return @("$File`: manifest is not a hashtable") }
    foreach ($k in @('Name', 'Version', 'Methods', 'Analyze')) {
        if (-not $Manifest.ContainsKey($k)) { [void]$err.Add("$File`: missing '$k'") }
    }
    if ($Manifest.Analyze -and -not ($Manifest.Analyze -is [scriptblock])) { [void]$err.Add("$File`: Analyze must be a scriptblock") }
    $names = @{}
    foreach ($m in @($Manifest.Methods)) {
        if ($names.ContainsKey($m.Name)) { [void]$err.Add("$File`: duplicate method '$($m.Name)'") }
        $names[$m.Name] = $true
        if (@('Primary', 'CrossCheck') -notcontains $m.Role) { [void]$err.Add("$File/$($m.Name): invalid Role '$($m.Role)'") }
        if ($script:AuditMethodScopes -notcontains $m.Scope) { [void]$err.Add("$File/$($m.Name): invalid Scope '$($m.Scope)'") }
        if (@($m.Transports).Count -eq 0) { [void]$err.Add("$File/$($m.Name): no Transports") }
        foreach ($t in @($m.Transports)) {
            if ($script:AuditTransports -notcontains $t) { [void]$err.Add("$File/$($m.Name): invalid transport '$t'") }
        }
        if (-not ($m.Script -is [scriptblock])) { [void]$err.Add("$File/$($m.Name): Script must be a scriptblock") }
        foreach ($vk in @('MinPSVersion', 'MinOSVersion')) {
            $vv = $null
            if ($m[$vk] -and -not [version]::TryParse([string]$m[$vk], [ref]$vv)) { [void]$err.Add("$File/$($m.Name): invalid $vk '$($m[$vk])'") }
        }
    }
    ,$err.ToArray()
}

function Get-AuditCollector {
    <#
      Laedt Collectors\*.Collector.ps1 (Dateien mit '_' am Anfang sind Vorlagen).
      Jede Datei gibt ein Manifest (Hashtable) zurueck.
    #>
    param([string[]]$Name, [string]$Path)
    if (-not $Path) { $Path = $script:AuditCollectorPath }
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -Filter '*.Collector.ps1' | Sort-Object Name)) {
        if ($file.Name.StartsWith('_')) { continue }
        $manifest = & $file.FullName
        $errors = Test-AuditCollectorManifest -Manifest $manifest -File $file.Name
        if ($errors.Count -gt 0) { throw ("Invalid collector manifest:`n" + ($errors -join "`n")) }
        if (-not $Name -or $Name -contains $manifest.Name) { $manifest }
    }
}

function Get-AuditCollectorPath {
    # Optional eigener Kollektor-Ordner (Config.Collection.CollectorPath), sonst der mitgelieferte.
    param([hashtable]$Config)
    $p = $null
    if ($Config -and $Config.Collection) { $p = $Config.Collection.CollectorPath }
    if ($p) { return (Expand-AuditPath $p) }
    $script:AuditCollectorPath
}

function Get-AuditApplicableMethod {
    param([Parameter(Mandatory)][hashtable]$Collector, [Parameter(Mandatory)][hashtable]$HostInfo)
    foreach ($m in @($Collector.Methods)) {
        if ($m.Scope -eq 'DomainController' -and -not $HostInfo.IsDomainController) { continue }
        $m
    }
}

# ----------------------------------------------------------------------------- Methodenausfuehrung

function New-AuditMethodScriptBlock {
    # Setzt RemoteHelpers vor das Methodenskript -> eigenstaendiger, PS-2.0-tauglicher Block.
    param([Parameter(Mandatory)][scriptblock]$Script)
    $nl = "`r`n"
    $text = 'param($ComputerName, $Target, $Options)' + $nl +
            $script:AuditRemoteHelpersText + $nl +
            '& {' + $nl + $Script.ToString() + $nl + '} $ComputerName $Target $Options'
    [scriptblock]::Create($text)
}

function New-AuditMethodResult {
    param([hashtable]$Collector, [hashtable]$Method, [hashtable]$HostInfo)
    @{
        Collector      = $Collector.Name
        CollectorVersion = $Collector.Version
        Method         = $Method.Name
        Role           = $Method.Role
        Host           = $HostInfo.Name
        HostInfo       = $HostInfo
        Transport      = ''
        Status         = 'Error'
        Message        = ''
        TransportNotes = New-Object System.Collections.ArrayList
        StartedAt      = Get-AuditUtcNow
        EndedAt        = $null
        Result         = $null
    }
}

function ConvertTo-AuditVersion {
    # '6.3 (9600)' -> 6.3 ; '5.1.14393.0' -> 5.1.14393.0 ; unlesbar -> $null
    param([string]$Text)
    if ($Text -match '(\d+\.\d+(\.\d+)*)') {
        $v = $null
        if ([version]::TryParse($matches[1], [ref]$v)) { return $v }
    }
    $null
}

function Test-AuditMethodCompatible {
    <#
      Prueft, ob eine Methode auf diesem Host/Transport laufen darf.
      Rueckgabe: $null (ok) oder Begruendung.

      Methoden koennen MinPSVersion (gilt fuer Ausfuehrung auf dem Ziel, also WinRM) und
      MinOSVersion (gilt immer, Vergleich mit operatingSystemVersion aus dem AD) deklarieren.
      Modus 'Auto'  : tatsaechliche Remote-PS-Version bzw. OS-Version; unbekannt -> erlaubt
      Modus 'Legacy': jeder Host wird wie Server 2008 / PowerShell 2.0 behandelt
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Method,
        [Parameter(Mandatory)][hashtable]$HostInfo,
        [Parameter(Mandatory)][string]$Transport,
        [string]$RemotePSVersion,
        [string]$Mode = 'Auto'
    )
    $legacy = ($Mode -eq 'Legacy')
    if ($Method.MinPSVersion -and $Transport -eq 'WinRM') {
        $need = [version]$Method.MinPSVersion
        $have = if ($legacy) { [version]'2.0' } else { ConvertTo-AuditVersion $RemotePSVersion }
        if ($have -and $have -lt $need) { return "requires PowerShell $need on target, found $have (mode $Mode)" }
    }
    if ($Method.MinOSVersion) {
        $need = [version]$Method.MinOSVersion
        $have = if ($legacy) { [version]'6.0' } else { ConvertTo-AuditVersion $HostInfo.OperatingSystemVersion }
        if ($have -and $have -lt $need) { return "requires OS version $need, host has $have (mode $Mode)" }
    }
    $null
}

function Get-AuditCoverageStatusFromKind {
    param([string]$Kind)
    switch ($Kind) {
        'AccessDenied' { 'AccessDenied' }
        'Unreachable'  { 'Unreachable' }
        'NotSupported' { 'NotSupported' }
        default        { 'Error' }
    }
}

function Invoke-AuditMethod {
    param(
        [Parameter(Mandatory)][hashtable]$Collector,
        [Parameter(Mandatory)][hashtable]$Method,
        [Parameter(Mandatory)][hashtable]$HostInfo,
        [Parameter(Mandatory)][hashtable]$Target,
        [Parameter(Mandatory)][hashtable]$Options,
        [object]$Session,
        [string]$SessionError,
        [string]$RemotePSVersion,
        [string]$CompatibilityMode = 'Auto'
    )
    $r = New-AuditMethodResult -Collector $Collector -Method $Method -HostInfo $HostInfo
    $sb = New-AuditMethodScriptBlock -Script $Method.Script
    $transports = @($Method.Transports)
    $component = $Collector.Name + '/' + $Method.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    for ($i = 0; $i -lt $transports.Count; $i++) {
        $t = $transports[$i]
        $isLast = ($i -eq $transports.Count - 1)
        $r.Transport = $t
        $incompatible = Test-AuditMethodCompatible -Method $Method -HostInfo $HostInfo -Transport $t `
            -RemotePSVersion $RemotePSVersion -Mode $CompatibilityMode
        if ($incompatible) {
            # Nicht ausfuehren ist eine Aussage ('Skipped'), kein Fund "nichts da"
            [void]$r.TransportNotes.Add("$t`: skipped - $incompatible")
            $r.Status = 'Skipped'; $r.Message = "$t`: skipped - $incompatible"
            Write-AuditLog -Level Info -Component $component -HostName $HostInfo.Name -Message "Transport $t skipped: $incompatible"
            continue
        }
        Write-AuditLog -Level Verbose -Component $component -HostName $HostInfo.Name -Message "Running via $t"
        try {
            if ($t -eq 'WinRM') {
                if ($null -eq $Session) {
                    [void]$r.TransportNotes.Add("WinRM: $SessionError")
                    $r.Status = 'Unreachable'; $r.Message = "WinRM: $SessionError"
                    if (-not $isLast) { Write-AuditLog -Level Verbose -Component $component -HostName $HostInfo.Name -Message 'No WinRM session - trying next transport' }
                    continue
                }
                $out = Invoke-Command -Session $Session -ScriptBlock $sb -ArgumentList @($null, $Target, $Options) -ErrorAction Stop
            }
            elseif ($t -eq 'Local') {
                $out = & $sb $null $Target $Options
            }
            else {
                # Rpc / Ldap: lokal ausgefuehrt, Ziel ueber ComputerName
                $out = & $sb $HostInfo.Name $Target $Options
            }
            $r.Result = @($out | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Records'] }) | Select-Object -Last 1
            if ($null -eq $r.Result) { throw 'Method script returned no result object' }
            $r.Status = 'Ok'; $r.Message = ''
            # Meldungen des Zielhosts ins Diagnose-Log uebernehmen
            foreach ($e in @($r.Result.Log)) {
                if ($null -eq $e) { continue }
                $lvl = [string]$e.Level
                if (@('Error', 'Warning', 'Info', 'Verbose', 'Debug') -notcontains $lvl) { $lvl = 'Info' }
                Write-AuditLog -Level $lvl -Component ('Remote:' + $component) -HostName $HostInfo.Name -Message ([string]$e.Message) -Time $e.Time
            }
            break
        }
        catch {
            $kind = Get-AuditErrorKind $_
            $msg = "$t`: " + $_.Exception.Message
            [void]$r.TransportNotes.Add($msg)
            $r.Status = Get-AuditCoverageStatusFromKind $kind
            $r.Message = $msg
            # Naechsten Transport nur versuchen, wenn der Fehler am Transport lag
            $transportBroken = ($kind -eq 'Unreachable') -or ($t -eq 'WinRM' -and $Session -and $Session.State -ne 'Opened')
            $fallback = $transportBroken -and -not $isLast
            Write-AuditLog -Level $(if ($fallback) { 'Info' } else { 'Warning' }) -Component $component -HostName $HostInfo.Name `
                -Message ("Failed via $t ($kind)" + $(if ($fallback) { ' - trying next transport' } else { '' })) -ErrorRecord $_
            if (-not $fallback) { break }
        }
    }
    $r.EndedAt = Get-AuditUtcNow
    $sw.Stop()
    $count = if ($r.Result) { @($r.Result.Records).Count } else { 0 }
    Write-AuditLog -Level $(if ($r.Status -in 'Ok', 'Skipped') { 'Verbose' } else { 'Warning' }) -Component $component -HostName $HostInfo.Name `
        -Message ("Finished: {0} via {1}, {2} records, {3:n1}s" -f $r.Status, $r.Transport, $count, $sw.Elapsed.TotalSeconds) `
        -Data $(if ($r.Status -ne 'Ok' -and $r.Message) { @{ Message = $r.Message } } else { $null })
    $r
}

function Get-AuditMethodOption {
    # Optionen, die ein Methodenskript bekommt: Kollektor-Konfiguration + Host-Kontext.
    param([hashtable]$Config, [hashtable]$Collector, [hashtable]$HostInfo)
    $o = @{}
    $section = $Config.Collectors[$Collector.Name]
    if ($section) { foreach ($k in $section.Keys) { $o[$k] = $section[$k] } }
    $o['HostName'] = $HostInfo.Name
    $o['HostShortName'] = $HostInfo.ShortName
    $o['IsDomainController'] = [bool]$HostInfo.IsDomainController
    $o['LogLevel'] = Get-AuditEffectiveLogLevel
    $o
}

function Invoke-AuditHostJob {
    <#
      Laeuft in einem Runspace des Pools: alle anwendbaren Methoden aller Kollektoren fuer einen Host.
      Ergebnisse landen sofort im geteilten Zustand, damit sie einen Timeout ueberleben.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$HostInfo,
        [Parameter(Mandatory)][string[]]$CollectorNames,
        [Parameter(Mandatory)][hashtable]$Target,
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$State,
        [string]$RunId = ''
    )
    $State.StartedAt = Get-AuditUtcNow
    $State.Phase = 'Prepare'
    # Eigener Runspace = eigene Modulinstanz -> Logging hier erneut initialisieren (ohne Bereinigung)
    if ($Config.Logging) { Initialize-AuditLogging -Settings $Config.Logging -RunId $RunId -NoMaintenance }
    Write-AuditLog -Level Verbose -Component 'HostJob' -HostName $HostInfo.Name -Message 'Host job started' `
        -Data @{ IsDomainController = [bool]$HostInfo.IsDomainController; OS = $HostInfo.OperatingSystem; OSVersion = $HostInfo.OperatingSystemVersion }
    $collectors = @(Get-AuditCollector -Name $CollectorNames -Path (Get-AuditCollectorPath $Config))
    $plan = foreach ($c in $collectors) { foreach ($m in Get-AuditApplicableMethod -Collector $c -HostInfo $HostInfo) { @{ Collector = $c; Method = $m } } }
    $plan = @($plan)
    if ($plan.Count -eq 0) { return }

    # Namensaufloesung - ohne sie ist jede Methode "Unreachable", nicht "nichts gefunden"
    $State.Phase = 'DNS'
    $dnsError = $null
    try { [void][System.Net.Dns]::GetHostAddresses($HostInfo.Name) } catch { $dnsError = $_.Exception.Message }
    if ($dnsError) { Write-AuditLog -Level Warning -Component 'HostJob' -HostName $HostInfo.Name -Message "DNS resolution failed: $dnsError" }

    $session = $null
    $sessionError = 'not attempted'
    $needsWinRM = @($plan | Where-Object { @($_.Method.Transports) -contains 'WinRM' }).Count -gt 0
    $needsHost = @($plan | Where-Object { @($_.Method.Transports | Where-Object { $_ -ne 'Ldap' -and $_ -ne 'Local' }).Count -gt 0 }).Count -gt 0
    if ($dnsError -and $needsHost) { $sessionError = "DNS: $dnsError" }
    elseif ($needsWinRM) {
        $State.Phase = 'WinRM'
        try {
            $timeoutMs = [int]$Config.Collection.ConnectTimeoutSeconds * 1000
            $opTimeoutMs = [int]$Config.Collection.HostTimeoutSeconds * 1000
            $opt = New-PSSessionOption -OpenTimeout $timeoutMs -OperationTimeout $opTimeoutMs -NoMachineProfile
            $session = New-PSSession -ComputerName $HostInfo.Name -SessionOption $opt -ErrorAction Stop
            $State.RemotePSVersion = [string](Invoke-Command -Session $session -ScriptBlock { $PSVersionTable.PSVersion.ToString() } -ErrorAction Stop)
            $sessionError = ''
            Write-AuditLog -Level Verbose -Component 'HostJob' -HostName $HostInfo.Name -Message "WinRM session open, remote PowerShell $($State.RemotePSVersion)"
        }
        catch {
            $sessionError = $_.Exception.Message
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue; $session = $null }
            Write-AuditLog -Level Info -Component 'HostJob' -HostName $HostInfo.Name -Message 'WinRM not available - methods will use their fallback transports' -ErrorRecord $_
        }
    }
    $State.WinRM = if ($session) { 'Ok' } else { $sessionError }

    try {
        foreach ($item in $plan) {
            $State.Phase = $item.Collector.Name + '/' + $item.Method.Name
            if ($dnsError -and (@($item.Method.Transports) -notcontains 'Ldap') -and (@($item.Method.Transports) -notcontains 'Local')) {
                $r = New-AuditMethodResult -Collector $item.Collector -Method $item.Method -HostInfo $HostInfo
                $r.Status = 'Unreachable'; $r.Message = "DNS: $dnsError"; $r.EndedAt = Get-AuditUtcNow
            }
            else {
                $opts = Get-AuditMethodOption -Config $Config -Collector $item.Collector -HostInfo $HostInfo
                try {
                    $r = Invoke-AuditMethod -Collector $item.Collector -Method $item.Method -HostInfo $HostInfo `
                        -Target $Target -Options $opts -Session $session -SessionError $sessionError `
                        -RemotePSVersion $State.RemotePSVersion -CompatibilityMode ([string]$Config.Collection.CompatibilityMode)
                }
                catch {
                    $r = New-AuditMethodResult -Collector $item.Collector -Method $item.Method -HostInfo $HostInfo
                    $r.Status = 'Error'; $r.Message = $_.Exception.Message; $r.EndedAt = Get-AuditUtcNow
                    Write-AuditLog -Level Error -Component ($item.Collector.Name + '/' + $item.Method.Name) -HostName $HostInfo.Name -Message 'Unexpected runner error' -ErrorRecord $_
                }
            }
            [void]$State.Results.Add($r)
        }
    }
    finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        $State.Phase = 'Done'
        Write-AuditLog -Level Verbose -Component 'HostJob' -HostName $HostInfo.Name -Message ("Host job done after {0:n1}s" -f ((Get-AuditUtcNow) - [datetime]$State.StartedAt).TotalSeconds)
    }
}

# ----------------------------------------------------------------------------- Orchestrierung

function Invoke-AuditCollection {
    <#
      Fuehrt alle Kollektoren gegen alle Hosts parallel aus.
      Status: optionale synchronisierte Hashtable fuer Fortschritt (GUI).
      Rueckgabe: Liste der Methodenergebnisse (inkl. synthetischer Timeout/Error-Ergebnisse).
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][hashtable]$Target,
        [Parameter(Mandatory)][object[]]$Hosts,
        [Parameter(Mandatory)][string[]]$CollectorNames,
        [hashtable]$Status,
        [string]$RunId = ''
    )
    if (-not $Status) { $Status = [hashtable]::Synchronized(@{}) }
    $Status.HostsTotal = $Hosts.Count
    $Status.HostsDone = 0
    $Status.Hosts = [hashtable]::Synchronized(@{})

    $collectors = @(Get-AuditCollector -Name $CollectorNames -Path (Get-AuditCollectorPath $Config))
    $max = [math]::Max(1, [int]$Config.Collection.MaxParallelHosts)
    $timeout = [timespan]::FromSeconds([int]$Config.Collection.HostTimeoutSeconds)

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $iss.ImportPSModule(@($script:AuditModuleManifest))
    $pool = [runspacefactory]::CreateRunspacePool(1, $max, $iss, $Host)
    $pool.Open()
    Write-AuditLog -Level Info -Component 'Runner' -Message ("Collecting from {0} hosts, {1} in parallel, host timeout {2}s, mode {3}" -f `
        $Hosts.Count, $max, [int]$timeout.TotalSeconds, $Config.Collection.CompatibilityMode) -Data @{ Collectors = $CollectorNames }

    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $Hosts) {
        $state = [hashtable]::Synchronized(@{
            StartedAt = $null; Phase = 'Queued'; WinRM = ''; RemotePSVersion = ''
            Results = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        })
        $Status.Hosts[$h.Name] = $state
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddCommand('Invoke-AuditHostJob').AddParameters(@{
            HostInfo = $h; CollectorNames = $CollectorNames; Target = $Target; Config = $Config; State = $state; RunId = $RunId
        })
        [void]$jobs.Add(@{ Ps = $ps; Handle = $ps.BeginInvoke(); Host = $h; State = $state; Done = $false; TimedOut = $false; JobError = '' })
    }

    while (@($jobs | Where-Object { -not $_.Done }).Count -gt 0) {
        foreach ($j in $jobs) {
            if ($j.Done) { continue }
            if ($j.Handle.IsCompleted) {
                try { [void]$j.Ps.EndInvoke($j.Handle) } catch { $j.JobError = $_.Exception.Message }
                if ($j.Ps.Streams.Error.Count -gt 0 -and -not $j.JobError) { $j.JobError = [string]$j.Ps.Streams.Error[0] }
                if ($j.JobError) { Write-AuditLog -Level Error -Component 'Runner' -HostName $j.Host.Name -Message "Host job failed: $($j.JobError)" }
                $j.Done = $true
                $j.Ps.Dispose()
                $Status.HostsDone++
            }
            elseif ($j.State.StartedAt -and ((Get-AuditUtcNow) - [datetime]$j.State.StartedAt) -gt $timeout) {
                # Nicht blockierend stoppen: ein haengender RPC-Aufruf darf den Lauf nicht festhalten
                [void]$j.Ps.BeginStop($null, $null)
                $j.TimedOut = $true
                Write-AuditLog -Level Warning -Component 'Runner' -HostName $j.Host.Name -Message ("Host timeout after {0}s in phase '{1}' - finished methods are kept" -f [int]$timeout.TotalSeconds, $j.State.Phase)
                $j.Done = $true
                $Status.HostsDone++
            }
        }
        Start-Sleep -Milliseconds 200
    }
    if (@($jobs | Where-Object { $_.TimedOut }).Count -gt 0) { [void]$pool.BeginClose($null, $null) }
    else { $pool.Close(); $pool.Dispose() }

    # Ergebnisse einsammeln und fehlende Methoden als Timeout/Error kennzeichnen
    $all = New-Object System.Collections.ArrayList
    foreach ($j in $jobs) {
        $got = @{}
        foreach ($r in @($j.State.Results)) {
            $r.HostWinRM = $j.State.WinRM
            $r.RemotePSVersion = $j.State.RemotePSVersion
            [void]$all.Add($r); $got[$r.Collector + '/' + $r.Method] = $true
        }
        foreach ($c in $collectors) {
            foreach ($m in Get-AuditApplicableMethod -Collector $c -HostInfo $j.Host) {
                if ($got.ContainsKey($c.Name + '/' + $m.Name)) { continue }
                $r = New-AuditMethodResult -Collector $c -Method $m -HostInfo $j.Host
                $r.EndedAt = Get-AuditUtcNow
                $r.HostWinRM = $j.State.WinRM
                if ($j.TimedOut) { $r.Status = 'Timeout'; $r.Message = "Host timeout after $([int]$timeout.TotalSeconds)s (phase: $($j.State.Phase))" }
                elseif ($j.JobError) { $r.Status = 'Error'; $r.Message = $j.JobError }
                else { $r.Status = 'Error'; $r.Message = 'No result returned' }
                [void]$all.Add($r)
            }
        }
    }
    $all.ToArray()
}

function ConvertTo-AuditCoverage {
    # Methodenergebnisse -> Coverage-Datensaetze (einer pro Host x Kollektor x Methode).
    param([Parameter(Mandatory)][string]$RunId, [object[]]$MethodResults, [string]$CollectedBy)
    foreach ($r in $MethodResults) {
        $res = $r.Result
        $pre = @{}
        if ($res -and $res.Preconditions) { foreach ($k in $res.Preconditions.Keys) { $pre[$k] = $res.Preconditions[$k] } }
        if ($r.HostWinRM) { $pre['WinRM'] = $r.HostWinRM }
        if ($r.RemotePSVersion) { $pre['RemotePSVersion'] = $r.RemotePSVersion }
        $notes = @()
        if ($r.TransportNotes) { $notes += @($r.TransportNotes) }
        if ($res -and $res.Notes) { $notes += @($res.Notes) }
        $msg = (@($r.Message) + $notes | Where-Object { $_ } | Select-Object -Unique) -join ' | '
        New-AuditCoverage -RunId $RunId -Source $r.Collector -HostName $r.Host -Method $r.Method -Role $r.Role `
            -Status $r.Status -Transport $r.Transport `
            -ResultCount $(if ($res) { @($res.Records).Count } else { 0 }) `
            -WindowStart $(if ($res) { $res.WindowStart }) -WindowEnd $(if ($res) { $res.WindowEnd }) `
            -Truncated $(if ($res) { [bool]$res.Truncated } else { $false }) `
            -Preconditions $pre -Message $msg -StartedAt $r.StartedAt -EndedAt $r.EndedAt -CollectedBy $CollectedBy
    }
}
