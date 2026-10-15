# Konfiguration: eingebaute Standardwerte, ueberlagert von Config\AdminAudit.config.json.

function Get-AuditDefaultConfig {
    @{
        ConfigVersion = 1
        Language      = 'de-DE'
        Authorization = @{
            # Eine Rolle fuer alle: Mitglieder dieser AD-Gruppe (auch verschachtelt) duerfen das Tool nutzen.
            AllowedGroup = 'GG-AdminAccountAudit'
        }
        TargetAccount = @{
            # Domaenen-Administrator = Domaenen-SID + RID 500, unabhaengig vom aktuellen Namen.
            Rid = 500
        }
        # Lokale RID-500-Konten der Member-Server sind ein anderes Konto. Standard: nicht melden,
        # aber in der Coverage zaehlen.
        IncludeLocalAdministrator = $false
        Scope = @{
            # Single | List | OU | AllComputers | AllServers
            Mode                     = 'AllServers'
            Hosts                    = @()
            SearchBase               = ''
            IncludeDomainControllers = $true
            OnlyEnabled              = $true
        }
        Collection = @{
            MaxParallelHosts      = 8
            HostTimeoutSeconds    = 900
            ConnectTimeoutSeconds = 20
            CollectorPath         = ''      # leer = mitgelieferter Ordner Collectors\
            # Auto   : Remote-PS-Version und OS-Version je Host erkennen, Methoden mit hoeheren
            #          Anforderungen dort ueberspringen (Coverage 'Skipped') und Fallbacks nutzen
            # Legacy : jeden Host wie Server 2008 / PowerShell 2.0 behandeln (GUI-Checkbox
            #          "Abwaertskompatibilitaetsmodus"), wenn die Erkennung nicht vertrauenswuerdig ist
            CompatibilityMode     = 'Auto'
        }
        Collectors = @{
            Logon = @{
                Enabled                    = $true
                LookbackDays               = 0       # 0 = alles, was im Log steht
                MaxEventsPerQuery          = 100000  # Schutz vor Riesen-Logs; Abschneiden wird in der Coverage markiert
                CrossCheckToleranceSeconds = 120     # Security-Log vs. TerminalServices/Winlogon
                DcAttributeToleranceSeconds = 300    # lastLogon/badPasswordTime vs. DC-Events
                ProfileToleranceSeconds    = 300
                EvidenceSamples            = 5       # Rohbelege je aggregiertem Fund (erste + letzte N)
            }
        }
        Storage = @{
            RunDirectory      = '%ProgramData%\AdminAccountAudit\runs'
            AuditLogDirectory = '%ProgramData%\AdminAccountAudit\audit'
            SettingsDirectory = '%APPDATA%\AdminAccountAudit\settings'
        }
        Smtp = @{
            Host           = ''
            Port           = 25
            From           = ''
            To             = @()
            EnableStartTls = $false
        }
    }
}

function Merge-AuditHashtable {
    # Ueberlagert $Base rekursiv mit $Override (Override gewinnt, unbekannte Schluessel werden uebernommen).
    param([hashtable]$Base, [hashtable]$Override)
    $result = @{}
    foreach ($k in $Base.Keys) { $result[$k] = $Base[$k] }
    if ($null -eq $Override) { return $result }
    foreach ($k in $Override.Keys) {
        if ($result[$k] -is [hashtable] -and $Override[$k] -is [hashtable]) {
            $result[$k] = Merge-AuditHashtable $result[$k] $Override[$k]
        }
        else { $result[$k] = $Override[$k] }
    }
    $result
}

function Get-AuditConfig {
    param([string]$Path)
    $config = Get-AuditDefaultConfig
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "Config file not found: $Path" }
        $json = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        $override = ConvertTo-AuditHashtable ($json | ConvertFrom-Json)
        Remove-AuditCommentKey $override
        $config = Merge-AuditHashtable $config $override
    }
    if (@('Auto', 'Legacy') -notcontains [string]$config.Collection.CompatibilityMode) {
        throw "Collection.CompatibilityMode must be 'Auto' or 'Legacy', got '$($config.Collection.CompatibilityMode)'"
    }
    $config
}

function Remove-AuditCommentKey {
    # Kommentar-Schluessel ("_comment", "_Irgendwas") auf allen Ebenen ignorieren
    param([hashtable]$Table)
    foreach ($k in @($Table.Keys)) {
        if ($k -like '_*') { $Table.Remove($k) }
        elseif ($Table[$k] -is [hashtable]) { Remove-AuditCommentKey $Table[$k] }
    }
}
