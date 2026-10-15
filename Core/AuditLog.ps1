# Eigenes Audit-Log des Tools: wer hat wann was abgefragt.
# Format: JSON Lines (eine Zeile pro Eintrag), Monatsdateien audit-YYYYMM.jsonl.
# Schreibfehler werden als Warnung gemeldet, brechen aber keinen Lauf ab.

$script:AuditLogDirectory = $null

function Set-AuditLogDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $script:AuditLogDirectory = Expand-AuditPath $Path
}

function Write-AuditLogEntry {
    param(
        [Parameter(Mandatory)][string]$Action,
        [hashtable]$Data = @{},
        [string]$RunId = '',
        [string]$User
    )
    if (-not $script:AuditLogDirectory) { return }
    try {
        if (-not $User) {
            try { $User = (Get-AuditCurrentIdentity).Name } catch { $User = [System.Environment]::UserName }
        }
        $entry = [ordered]@{
            Time    = ConvertTo-AuditIsoString (Get-AuditUtcNow)
            User    = $User
            Machine = [System.Environment]::MachineName
            Process = $PID
            Action  = $Action
            RunId   = $RunId
            Data    = ConvertTo-AuditSerializable $Data
        }
        if (-not (Test-Path -LiteralPath $script:AuditLogDirectory)) {
            [void](New-Item -ItemType Directory -Path $script:AuditLogDirectory -Force)
        }
        $file = Join-Path $script:AuditLogDirectory ('audit-' + (Get-Date -Format 'yyyyMM') + '.jsonl')
        $line = (New-Object psobject -Property $entry | ConvertTo-Json -Depth 6 -Compress)
        [System.IO.File]::AppendAllText($file, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
    }
    catch {
        Write-Warning "Audit log write failed: $($_.Exception.Message)"
    }
}
