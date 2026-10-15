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
    Write-AuditLogEntry -Action 'RunStart' -RunId $runId -Data @{ Scope = $Config.Scope; Collectors = $Collector }

    try {
        if (-not $Target) { $Target = Resolve-AuditTargetAccount -Rid ([int]$Config.TargetAccount.Rid) }

        # Wer als Zielkonto sammelt, verfaelscht das Ergebnis (eigene Anmeldungen ueberall).
        if ($identity.Sid -eq $Target.Sid) {
            [void]$warnings.Add((Get-AuditString -Key 'Warning.RunningAsTarget' -Arguments @($Target.Display)))
        }

        $dcs = @(Get-AuditDomainController)
        if (-not $Hosts) { $Hosts = @(Resolve-AuditScope -ScopeConfig $Config.Scope -DomainControllers $dcs) }
        if ($Hosts.Count -eq 0) { throw (Get-AuditString -Key 'Error.NoHosts') }

        $collectors = @(Get-AuditCollector -Name $Collector -Path (Get-AuditCollectorPath $Config) | Where-Object {
            $section = $Config.Collectors[$_.Name]
            -not $section -or $section.Enabled -ne $false
        })
        $names = @($collectors | ForEach-Object { $_.Name })
        Write-AuditLogEntry -Action 'RunScope' -RunId $runId -Data @{
            Target = $Target.Display; TargetSid = $Target.Sid; Hosts = @($Hosts | ForEach-Object { $_.Name }); Collectors = $names
        }

        $Status.Phase = 'Collect'
        $results = Invoke-AuditCollection -Config $Config -Target $Target -Hosts $Hosts -CollectorNames $names -Status $Status

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
                foreach ($f in @(& $c.Analyze $context $mine $Target $optsAll $Hosts)) { [void]$findings.Add($f) }
            }
            catch {
                [void]$warnings.Add((Get-AuditString -Key 'Warning.AnalyzeFailed' -Arguments @($c.Name, $_.Exception.Message)))
            }
        }

        $coverage = @(ConvertTo-AuditCoverage -RunId $runId -MethodResults $results -CollectedBy $identity.Name)
        $run = New-AuditRun -RunId $runId -StartedAt $started -StartedBy $identity.Name -ToolVersion $script:AuditToolVersion `
            -Scope $Config.Scope -Hosts $Hosts -Target $Target -Collectors $names -Warnings $warnings.ToArray() `
            -Findings $findings.ToArray() -Coverage $coverage

        if (-not $NoSave) {
            $path = Save-AuditRun -Run $run -Directory $Config.Storage.RunDirectory
            $run | Add-Member -NotePropertyName SavedTo -NotePropertyValue $path
        }
        Write-AuditLogEntry -Action 'RunEnd' -RunId $runId -Data @{
            Findings = $findings.Count; Coverage = $coverage.Count
            NotOk = @($coverage | Where-Object { $_.Status -ne 'Ok' }).Count; Warnings = $warnings.Count
        }
        $Status.Phase = 'Done'
        $run
    }
    catch {
        Write-AuditLogEntry -Action 'RunFailed' -RunId $runId -Data @{ Error = $_.Exception.Message }
        $Status.Phase = 'Failed'
        throw
    }
}
