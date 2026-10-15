# Ein vollstaendiger Sammellauf: Zielkonto -> Scope -> Sammlung -> Analyse -> Speichern.

function Invoke-AdminAuditRun {
    <#
      Config     : Get-AuditConfig
      Collector  : Namen; leer = alle aktivierten Kollektoren
      Hosts      : optionale feste Host-Liste (sonst aus Config.Scope)
      Status     : optionale synchronisierte Hashtable fuer Fortschritt
      Rueckgabe  : AdminAudit.Run (zusaetzlich als JSON gespeichert, Pfad in .SavedTo)
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [string[]]$Collector,
        [object[]]$Hosts,
        [hashtable]$Target,
        [hashtable]$Status,
        [switch]$NoSave
    )
    $runId = New-AuditId
    $started = Get-AuditUtcNow
    $identity = Get-AuditCurrentIdentity
    $warnings = New-Object System.Collections.ArrayList
    if (-not $Status) { $Status = [hashtable]::Synchronized(@{}) }
    $Status.Phase = 'Prepare'

    Set-AuditLogDirectory -Path $Config.Storage.AuditLogDirectory
    if ($Config.Logging) { Initialize-AuditLogging -Settings $Config.Logging -RunId $runId }
    $swRun = [System.Diagnostics.Stopwatch]::StartNew()
    Write-AuditLog -Level Info -Component 'Run' -Message "Run started by $($identity.Name) (tool $script:AuditToolVersion)" `
        -Data @{ Scope = $Config.Scope.Mode; CompatibilityMode = $Config.Collection.CompatibilityMode; LogLevel = (Get-AuditLogLevel).Level }
    if (Test-AuditLogLevel Debug) {
        $cfgView = Merge-AuditHashtable $Config @{}
        $cfgView.Logging = @{}; foreach ($k in $Config.Logging.Keys) { if ($k -ne 'Sink') { $cfgView.Logging[$k] = $Config.Logging[$k] } }
        Write-AuditLog -Level Debug -Component 'Run' -Message 'Effective configuration' -Data $cfgView
    }
    Write-AuditLogEntry -Action 'RunStart' -RunId $runId -Data @{ Scope = $Config.Scope; Collectors = $Collector }

    try {
        if (-not $Target) { $Target = Resolve-AuditTargetAccount -Rid ([int]$Config.TargetAccount.Rid) }
        Write-AuditLog -Level Info -Component 'Run' -Message "Target account $($Target.Display) ($($Target.Sid))" `
            -Data @{ DistinguishedName = $Target.DistinguishedName; NameVariants = $Target.NameVariants }

        # Wer als Zielkonto sammelt, verfaelscht das Ergebnis (eigene Anmeldungen ueberall).
        if ($identity.Sid -eq $Target.Sid) {
            [void]$warnings.Add((Get-AuditString -Key 'Warning.RunningAsTarget' -Arguments @($Target.Display)))
            Write-AuditLog -Level Warning -Component 'Run' -Message 'Tool is running as the target account - own logons will appear in the results'
        }

        $dcs = @(Get-AuditDomainController)
        if (-not $Hosts) { $Hosts = @(Resolve-AuditScope -ScopeConfig $Config.Scope -DomainControllers $dcs) }
        if ($Hosts.Count -eq 0) { throw (Get-AuditString -Key 'Error.NoHosts') }
        Write-AuditLog -Level Info -Component 'Run' -Message ("Scope resolved: {0} hosts, {1} domain controllers" -f $Hosts.Count, @($Hosts | Where-Object { $_.IsDomainController }).Count)
        Write-AuditLog -Level Verbose -Component 'Run' -Message 'Hosts in scope' -Data @{ Hosts = @($Hosts | ForEach-Object { $_.Name + $(if ($_.IsDomainController) { ' (DC)' } else { '' }) + ' ' + $_.OperatingSystemVersion }) }

        $collectors = @(Get-AuditCollector -Name $Collector -Path (Get-AuditCollectorPath $Config) | Where-Object {
            $section = $Config.Collectors[$_.Name]
            -not $section -or $section.Enabled -ne $false
        })
        $names = @($collectors | ForEach-Object { $_.Name })
        Write-AuditLogEntry -Action 'RunScope' -RunId $runId -Data @{
            Target = $Target.Display; TargetSid = $Target.Sid; Hosts = @($Hosts | ForEach-Object { $_.Name }); Collectors = $names
        }

        $Status.Phase = 'Collect'
        $results = Invoke-AuditCollection -Config $Config -Target $Target -Hosts $Hosts -CollectorNames $names -Status $Status -RunId $runId

        $Status.Phase = 'Analyze'
        $findings = New-Object System.Collections.ArrayList
        foreach ($c in $collectors) {
            $context = @{
                RunId = $runId; CollectedAt = Get-AuditUtcNow; CollectedBy = $identity.Name
                CollectorVersion = $c.Version; Source = $c.Name
            }
            $mine = @($results | Where-Object { $_.Collector -eq $c.Name })
            $opts = $Config.Collectors[$c.Name]; if (-not $opts) { $opts = @{} }
            $optsAll = @{}; foreach ($k in $opts.Keys) { $optsAll[$k] = $opts[$k] }
            $optsAll['IncludeLocalAdministrator'] = [bool]$Config.IncludeLocalAdministrator
            try {
                $before = $findings.Count
                foreach ($f in @(& $c.Analyze $context $mine $Target $optsAll $Hosts)) { [void]$findings.Add($f) }
                Write-AuditLog -Level Info -Component $c.Name -Message ("Analysis produced {0} findings" -f ($findings.Count - $before))
            }
            catch {
                [void]$warnings.Add((Get-AuditString -Key 'Warning.AnalyzeFailed' -Arguments @($c.Name, $_.Exception.Message)))
                Write-AuditLog -Level Error -Component $c.Name -Message 'Analysis failed' -ErrorRecord $_
            }
        }

        $coverage = @(ConvertTo-AuditCoverage -RunId $runId -MethodResults $results -CollectedBy $identity.Name)
        $run = New-AuditRun -RunId $runId -StartedAt $started -StartedBy $identity.Name -ToolVersion $script:AuditToolVersion `
            -Scope $Config.Scope -Hosts $Hosts -Target $Target -Collectors $names -Warnings $warnings.ToArray() `
            -Findings $findings.ToArray() -Coverage $coverage

        if (-not $NoSave) {
            $path = Save-AuditRun -Run $run -Directory $Config.Storage.RunDirectory
            $run | Add-Member -NotePropertyName SavedTo -NotePropertyValue $path
            Write-AuditLog -Level Info -Component 'Run' -Message "Run saved to $path"
        }
        $notOk = @($coverage | Where-Object { $_.Status -ne 'Ok' })
        $swRun.Stop()
        Write-AuditLog -Level $(if ($notOk.Count -gt 0) { 'Warning' } else { 'Info' }) -Component 'Run' `
            -Message ("Run finished in {0:n1}s: {1} findings, {2} discrepancies, {3}/{4} checks not OK" -f $swRun.Elapsed.TotalSeconds,
                $findings.Count, @($findings | Where-Object { Test-AuditDiscrepancy $_ }).Count, $notOk.Count, $coverage.Count)
        Write-AuditLogEntry -Action 'RunEnd' -RunId $runId -Data @{
            Findings = $findings.Count; Coverage = $coverage.Count
            NotOk = @($coverage | Where-Object { $_.Status -ne 'Ok' }).Count; Warnings = $warnings.Count
        }
        $Status.Phase = 'Done'
        $run
    }
    catch {
        Write-AuditLogEntry -Action 'RunFailed' -RunId $runId -Data @{ Error = $_.Exception.Message }
        Write-AuditLog -Level Error -Component 'Run' -Message 'Run failed' -ErrorRecord $_
        $Status.Phase = 'Failed'
        throw
    }
}
