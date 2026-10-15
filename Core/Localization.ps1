# Zweisprachigkeit (de-DE / en-US).
#
# Texte liegen als JSON unter Localization\<Kultur>.json (UTF-8, damit Umlaute auch
# unter Windows PowerShell 5.1 korrekt ankommen). Fund-Objekte speichern zusaetzlich
# zum gerenderten Detail-Text den Schluessel und die Argumente, damit GUI und Report
# jederzeit in der anderen Sprache neu rendern koennen.

$script:AuditStrings = @{}
$script:AuditLanguage = 'de-DE'
$script:AuditSupportedLanguages = @('de-DE', 'en-US')

function Import-AuditLocalization {
    param([Parameter(Mandatory)][string]$Path)
    foreach ($lang in $script:AuditSupportedLanguages) {
        $file = Join-Path $Path ($lang + '.json')
        if (-not (Test-Path -LiteralPath $file)) { continue }
        $json = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)
        $script:AuditStrings[$lang] = ConvertTo-AuditHashtable ($json | ConvertFrom-Json)
    }
}

function Get-AuditSupportedLanguage { $script:AuditSupportedLanguages }

function Get-AuditLanguage { $script:AuditLanguage }

function Set-AuditLanguage {
    param([Parameter(Mandatory)][string]$Language)
    if ($script:AuditSupportedLanguages -notcontains $Language) {
        throw "Unsupported language '$Language'. Supported: $($script:AuditSupportedLanguages -join ', ')"
    }
    $script:AuditLanguage = $Language
}

function Get-AuditString {
    <#
      Liefert einen lokalisierten Text. Argumente werden mit der Kultur der Sprache
      formatiert. Ein String-Argument der Form '@Schluessel' wird selbst uebersetzt
      (z. B. '@LogonType.10' -> 'RemoteInteractive (RDP)').
      Fallback: en-US, danach der Schluessel selbst - es wird nie geworfen.
    #>
    param(
        [Parameter(Mandatory)][string]$Key,
        [object[]]$Arguments = @(),
        [string]$Language = $script:AuditLanguage
    )
    $template = $null
    foreach ($l in @($Language, 'en-US')) {
        $table = $script:AuditStrings[$l]
        if ($table -and $table.ContainsKey($Key)) { $template = [string]$table[$Key]; $Language = $l; break }
    }
    if ($null -eq $template) {
        if ($Arguments.Count -gt 0) { return ($Key + ' ' + ($Arguments -join ' | ')) }
        return $Key
    }
    if ($Arguments.Count -eq 0) { return $template }

    $culture = [System.Globalization.CultureInfo]::GetCultureInfo($Language)
    $resolved = foreach ($a in $Arguments) {
        if ($a -is [string] -and $a.Length -gt 1 -and $a[0] -eq '@') {
            Get-AuditString -Key $a.Substring(1) -Language $Language
        }
        elseif ($null -eq $a -or ($a -is [string] -and $a -eq '')) { '-' }
        else { $a }
    }
    try { return [string]::Format($culture, $template, [object[]]@($resolved)) }
    catch { return ($template + ' [' + ($Arguments -join ' | ') + ']') }
}

function ConvertTo-AuditDetailArgument {
    # Macht Detail-Argumente sprachneutral und JSON-tauglich: Zeitpunkte werden
    # als lokale Zeit "yyyy-MM-dd HH:mm:ss" eingefroren.
    param([object[]]$Arguments)
    $out = foreach ($a in $Arguments) {
        if ($a -is [datetime]) {
            $a.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        }
        elseif ($null -eq $a) { '' }
        else { $a }
    }
    ,@($out)
}
