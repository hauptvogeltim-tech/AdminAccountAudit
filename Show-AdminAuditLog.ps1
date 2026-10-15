<#
.SYNOPSIS
    Zeigt und filtert das Diagnose-Log von AdminAccountAudit.

.DESCRIPTION
    Liest die Dateien diag-*.log (Text- oder JSON-Format) aus Logging.Directory der Konfiguration
    oder aus -Directory. Mit -Follow werden neue Eintraege fortlaufend angezeigt (wie tail -f).

.PARAMETER Level
    Nur Eintraege dieses Levels und schwerer: Error | Warning | Info | Verbose | Debug (Standard: Info).

.PARAMETER RunId
    Nur Eintraege eines Laufs (die ersten 8 Zeichen der RunId genuegen).

.PARAMETER HostName
    Nur Eintraege zu Hosts, deren Name diesen Text enthaelt.

.PARAMETER Component
    Nur Eintraege von Komponenten, deren Name diesen Text enthaelt (z. B. Runner, SecurityLog, Remote).

.PARAMETER Pattern
    Regulaerer Ausdruck auf den Meldungstext.

.PARAMETER Last
    Nur die letzten N Treffer (Standard: 200, 0 = alle).

.PARAMETER Follow
    Danach weiterlaufen und neue Eintraege anzeigen (Strg+C beendet).

.PARAMETER PassThru
    Objekte ausgeben statt formatierter Zeilen (zum Weiterverarbeiten, z. B. Out-GridView).

.EXAMPLE
    .\Show-AdminAuditLog.ps1 -Level Warning -Last 50

.EXAMPLE
    .\Show-AdminAuditLog.ps1 -RunId 3f2a91c0 -HostName srv01 -Level Debug

.EXAMPLE
    .\Show-AdminAuditLog.ps1 -Follow -Level Verbose

.EXAMPLE
    .\Show-AdminAuditLog.ps1 -Level Warning -Last 0 -PassThru | Out-GridView
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$Directory,
    [ValidateSet('Error', 'Warning', 'Info', 'Verbose', 'Debug')][string]$Level = 'Info',
    [string]$RunId,
    [string]$HostName,
    [string]$Component,
    [string]$Pattern,
    [int]$Last = 200,
    [switch]$Follow,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AdminAudit.psd1') -Force

if (-not $Directory) {
    if (-not $ConfigPath) { $ConfigPath = Join-Path (Join-Path $PSScriptRoot 'Config') 'AdminAudit.config.json' }
    $config = Get-AuditConfig -Path $ConfigPath
    $Directory = Expand-AuditPath $config.Logging.Directory
}
if (-not (Test-Path -LiteralPath $Directory)) { throw "Log directory not found: $Directory" }

$colors = @{ Error = 'Red'; Warning = 'Yellow'; Info = 'Gray'; Verbose = 'DarkGray'; Debug = 'DarkCyan' }
function Out-Entry($e) {
    if ($PassThru) { return $e }
    $time = if ($e.Time) { ([datetime]$e.Time).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
    $h = if ($e.Host) { $e.Host } else { '-' }
    $line = '{0} {1,-7} {2,-22} {3,-22} {4}' -f $time, $e.Level, $e.Component, $h, $e.Message
    if ($e.Data -and $e.Data.Count -gt 0) {
        $line += '  ' + (($e.Data.Keys | ForEach-Object { '{0}={1}' -f $_, ($(if ($e.Data[$_] -is [array]) { $e.Data[$_] -join ',' } else { $e.Data[$_] })) }) -join '; ')
    }
    $color = $colors[$e.Level]; if (-not $color) { $color = 'Gray' }
    Write-Host $line -ForegroundColor $color
}

$filter = @{ Directory = $Directory; Level = $Level }
foreach ($k in 'RunId', 'HostName', 'Component', 'Pattern') { if ($PSBoundParameters.ContainsKey($k)) { $filter[$k] = $PSBoundParameters[$k] } }

$entries = @(Get-AuditLogEntry @filter -Last $Last)
foreach ($e in $entries) { Out-Entry $e }
if (-not $Follow) { return }

# Weiterlaufen: nur Eintraege nach dem zuletzt gezeigten Zeitpunkt
$since = if ($entries.Count -gt 0) { $entries[-1].Time } else { Get-AuditUtcNow }
$seen = @{}
foreach ($e in $entries) { $seen[('{0}|{1}|{2}' -f (ConvertTo-AuditIsoString $e.Time), $e.Host, $e.Message)] = $true }
while ($true) {
    Start-Sleep -Seconds 1
    foreach ($e in @(Get-AuditLogEntry @filter -Since $since)) {
        $key = '{0}|{1}|{2}' -f (ConvertTo-AuditIsoString $e.Time), $e.Host, $e.Message
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        Out-Entry $e
        if ($e.Time -gt $since) { $since = $e.Time }
    }
}
