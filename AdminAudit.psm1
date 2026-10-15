# AdminAccountAudit - Kernmodul.
# Laedt Core\*.ps1, Lokalisierung und kennt den Kollektor-Ordner.

$script:AuditToolVersion = '0.2.0'
$script:AuditModuleRoot = $PSScriptRoot
$script:AuditModuleManifest = Join-Path $PSScriptRoot 'AdminAudit.psd1'
$script:AuditCollectorPath = Join-Path $PSScriptRoot 'Collectors'

foreach ($file in @('Common', 'Localization', 'Config', 'Finding', 'TargetAccount', 'Scope', 'CrossCheck',
                    'RemoteHelpers', 'Runner', 'AuditLog', 'ResultStore', 'Run')) {
    . (Join-Path (Join-Path $PSScriptRoot 'Core') "$file.ps1")
}

# Text der Remote-Hilfsfunktionen: wird vor jedes Methodenskript gesetzt
$script:AuditRemoteHelpersText = [System.IO.File]::ReadAllText((Join-Path (Join-Path $PSScriptRoot 'Core') 'RemoteHelpers.ps1'))

Import-AuditLocalization -Path (Join-Path $PSScriptRoot 'Localization')

function Get-AuditToolVersion { $script:AuditToolVersion }

Export-ModuleMember -Function *-Audit*, Invoke-AdminAuditRun
