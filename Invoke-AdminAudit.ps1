<#
.SYNOPSIS
    Kommandozeilen-Einstieg: inventarisiert Abhaengigkeiten vom Domaenen-Administrator (read-only).

.DESCRIPTION
    Bis die GUI fertig ist, ist dies der Weg fuer Testlaeufe. Ergebnis wird als JSON unter
    Storage.RunDirectory gespeichert (spaeter in der GUI ladbar) und optional als CSV exportiert.

    Laeuft unter der Identitaet, mit der das Skript gestartet wurde (Kerberos, keine Passwortabfrage).
    Bitte NICHT als Administrator starten - die eigenen Anmeldungen wuerden das Ergebnis verfaelschen.

.PARAMETER ConfigPath
    Konfigurationsdatei. Standard: Config\AdminAudit.config.json neben diesem Skript.

.PARAMETER ComputerName
    Ueberschreibt den Scope aus der Konfiguration mit einer festen Host-Liste. DCs werden
    weiterhin ergaenzt, wenn Scope.IncludeDomainControllers gesetzt ist.

.PARAMETER Collector
    Nur diese Kollektoren ausfuehren (Standard: alle aktivierten).

.PARAMETER Language
    de-DE oder en-US (Standard: aus der Konfiguration).

.PARAMETER LegacyMode
    Abwaertskompatibilitaetsmodus: jeden Host wie Server 2008 / PowerShell 2.0 behandeln.
    Methoden, die mehr voraussetzen, werden uebersprungen (Coverage 'Skipped'), es greifen die
    Fallback-Methoden. Standard ist 'Auto' (Erkennung je Host). Entspricht der spaeteren GUI-Checkbox.

.PARAMETER CsvPath
    Optional: Funde zusaetzlich als CSV (Semikolon, UTF-8) schreiben.

.EXAMPLE
    .\Invoke-AdminAudit.ps1 -ComputerName srv01,srv02 -CsvPath .\funde.csv

.EXAMPLE
    .\Invoke-AdminAudit.ps1 -Language en-US
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string[]]$ComputerName,
    [string[]]$Collector,
    [ValidateSet('de-DE', 'en-US')][string]$Language,
    [switch]$LegacyMode,
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdminAudit.psd1') -Force

if (-not $ConfigPath) { $ConfigPath = Join-Path (Join-Path $PSScriptRoot 'Config') 'AdminAudit.config.json' }
$config = Get-AuditConfig -Path $ConfigPath
if ($Language) { $config.Language = $Language }
if ($LegacyMode) { $config.Collection.CompatibilityMode = 'Legacy' }
Set-AuditLanguage $config.Language

if ($ComputerName) {
    $config.Scope.Mode = 'List'
    $config.Scope.Hosts = @($ComputerName)
}

$status = [hashtable]::Synchronized(@{})
$p = @{ Config = $config; Status = $status }
if ($Collector) { $p.Collector = $Collector }

# Lauf im Hintergrund-Runspace, damit hier Fortschritt angezeigt werden kann
$ps = [powershell]::Create()
[void]$ps.AddScript({
    param($ModulePath, $Params)
    Import-Module $ModulePath
    Set-AuditLanguage $Params.Config.Language
    Invoke-AdminAuditRun @Params
}).AddArgument((Join-Path $PSScriptRoot 'AdminAudit.psd1')).AddArgument($p)
$handle = $ps.BeginInvoke()
while (-not $handle.IsCompleted) {
    $done = [int]$status.HostsDone; $total = [int]$status.HostsTotal
    $pct = if ($total -gt 0) { [int](100 * $done / $total) } else { 0 }
    Write-Progress -Activity 'AdminAccountAudit' -Status ("{0} - {1}/{2}" -f $status.Phase, $done, $total) -PercentComplete $pct
    Start-Sleep -Milliseconds 500
}
Write-Progress -Activity 'AdminAccountAudit' -Completed
$run = $ps.EndInvoke($handle) | Select-Object -Last 1
foreach ($e in $ps.Streams.Error) { Write-Error $e -ErrorAction Continue }
foreach ($w in $ps.Streams.Warning) { Write-Warning $w }
$ps.Dispose()
if (-not $run) { throw 'Run produced no result.' }

foreach ($w in @($run.Warnings)) { Write-Warning $w }

$disc = @($run.Findings | Where-Object { Test-AuditDiscrepancy $_ })
$ok = @($run.Coverage | Where-Object { $_.Status -eq 'Ok' })
Write-Host ''
Write-Host (Get-AuditString -Key 'Cli.Summary' -Arguments @($run.RunId, @($run.Findings).Count, $disc.Count, $ok.Count, @($run.Coverage).Count)) -ForegroundColor Cyan
if ($run.SavedTo) { Write-Host (Get-AuditString -Key 'Cli.SavedTo' -Arguments @($run.SavedTo)) }

$problems = @($run.Coverage | Where-Object { $_.Status -ne 'Ok' })
if ($problems.Count -gt 0) {
    Write-Host ''
    Write-Host (Get-AuditString -Key 'Cli.CoverageProblems') -ForegroundColor Yellow
    $problems | Sort-Object Host, Method | Format-Table Host, Method, Status, Transport, Message -AutoSize -Wrap | Out-Host
}

$run.Findings | Sort-Object Host, ObjectType, Timestamp |
    Format-Table Host, ObjectType, Timestamp, CrossCheck, Confidence, Detail -AutoSize -Wrap | Out-Host

if ($CsvPath) {
    $run.Findings | Select-Object Source, Host, Account, ObjectType, Detail,
        @{ n = 'Timestamp'; e = { ConvertTo-AuditIsoString $_.Timestamp } }, Method, Confidence,
        AccountScope, AccountMatch, CrossCheck, CrossCheckNote, CorrelationKey, RunId, CollectedBy,
        @{ n = 'CollectedAt'; e = { ConvertTo-AuditIsoString $_.CollectedAt } } |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Delimiter ';' -Encoding UTF8
    Write-Host "CSV: $CsvPath"
}
