# Gemeinsame Hilfsfunktionen (lokal, Windows PowerShell 5.1 / PowerShell 7).

function Get-AuditUtcNow {
    [System.DateTime]::UtcNow
}

function ConvertTo-AuditIsoString {
    # Zeitpunkte werden immer als ISO 8601 in UTC gespeichert ("o"-Format).
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    $dt = [datetime]$Value
    if ($dt.Kind -eq [System.DateTimeKind]::Unspecified) {
        $dt = [System.DateTime]::SpecifyKind($dt, [System.DateTimeKind]::Utc)
    }
    $dt.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-AuditTimeString {
    # Liest ISO-Zeitstempel (von Remote-Skripten oder aus Ergebnisdateien) als UTC-DateTime.
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime() }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
              [System.Globalization.DateTimeStyles]::AssumeUniversal
    $result = [datetime]::MinValue
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$result)) {
        return $result
    }
    return $null
}

function ConvertFrom-AuditFileTime {
    # AD-Large-Integer (FILETIME) -> UTC-DateTime. 0 und "nie" (Int64.MaxValue) -> $null.
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    $n = [int64]0
    if (-not [int64]::TryParse([string]$Value, [ref]$n)) { return $null }
    if ($n -le 0 -or $n -eq [int64]::MaxValue) { return $null }
    try { return [datetime]::FromFileTimeUtc($n) } catch { return $null }
}

function Expand-AuditPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    [System.Environment]::ExpandEnvironmentVariables($Path)
}

function New-AuditId {
    [guid]::NewGuid().ToString()
}

function ConvertTo-AuditHashtable {
    # Wandelt PSCustomObjects (z. B. aus ConvertFrom-Json) rekursiv in Hashtables.
    param([object]$InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $InputObject.Keys) { $h[$k] = ConvertTo-AuditHashtable $InputObject[$k] }
        return $h
    }
    if ($InputObject -is [string]) { return $InputObject }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($i in $InputObject) { [void]$list.Add((ConvertTo-AuditHashtable $i)) }
        return ,($list.ToArray())
    }
    if ($InputObject -is [psobject] -and $InputObject.PSObject.Properties.Count -gt 0 -and
        -not ($InputObject -is [ValueType])) {
        $h = @{}
        foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-AuditHashtable $p.Value }
        return $h
    }
    return $InputObject
}

function Get-AuditProperty {
    # Liest einen Wert aus Hashtable oder Objekt, ohne bei fehlendem Feld zu werfen.
    param([object]$Object, [string]$Name, [object]$Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $Default
}

function Get-AuditCurrentIdentity {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        [pscustomobject]@{ Name = $id.Name; Sid = $id.User.Value }
    }
    catch {
        # Nicht-Windows (nur Tests)
        [pscustomobject]@{ Name = [System.Environment]::UserName; Sid = '' }
    }
}
