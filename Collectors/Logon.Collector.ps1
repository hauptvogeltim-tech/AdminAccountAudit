# Kollektor "Logon" - Referenzmuster fuer alle weiteren Kollektoren.
#
# Primaer   : Security-Log auf jedem Host (4624/4625/4634/4647/4648/4672),
#             auf DCs zusaetzlich 4768/4769/4771/4776/4740/4723/4724/4738.
# Gegenprobe: unabhaengige Quellen fuer dieselben Aussagen
#   - TerminalServices-Logs (LSM 21-25, RCM 1149)    <-> interaktive/RDP-Anmeldungen
#   - System-Log Winlogon 7001/7002 (UserSid)         <-> interaktive Anmeldungen
#   - Registry ProfileList (Profil + Ladezeit)        <-> "hat sich hier je interaktiv angemeldet"
#   - AD-Attribute je DC (lastLogon, badPasswordTime, pwdLastSet, lastLogonTimestamp)
#                                                     <-> Kerberos/NTLM-Ereignisse auf diesem DC
#
# Methodenskripte laufen auf dem Zielhost (WinRM) oder lokal mit -ComputerName (RPC/LDAP)
# und muessen PowerShell-2.0-kompatibel bleiben (siehe Core\RemoteHelpers.ps1).

@{
    Name    = 'Logon'
    Version = '1.0.0'

    Methods = @(
        # ------------------------------------------------------------------ Security-Log (primaer)
        @{
            Name       = 'SecurityLog'
            Role       = 'Primary'
            Scope      = 'Host'
            Transports = @('WinRM', 'Rpc')
            Script     = {
                param($ComputerName, $Target, $Options)
                $res = New-AuditRemoteResult
                $max = [int]$Options.MaxEventsPerQuery
                $tf = Get-AuditTimeFilter ([int]$Options.LookbackDays)
                $sid = $Target.Sid

                $selects = @()
                $selects += @{ Path = 'Security'; Query = "*[System[(" + (New-AuditXPathOr 'EventID' @(4624, 4625, 4634, 4647)) + ")$tf] and EventData[Data[@Name='TargetUserSid']='$sid']]" }
                $selects += @{ Path = 'Security'; Query = "*[System[(" + (New-AuditXPathOr 'EventID' @(4648, 4672)) + ")$tf] and EventData[Data[@Name='SubjectUserSid']='$sid']]" }
                foreach ($n in @($Target.NameVariants)) {
                    $selects += @{ Path = 'Security'; Query = "*[System[(" + (New-AuditXPathOr 'EventID' @(4625, 4648, 4776)) + ")$tf] and EventData[Data[@Name='TargetUserName']='$n']]" }
                }
                if ($Options.IsDomainController) {
                    $selects += @{ Path = 'Security'; Query = "*[System[(" + (New-AuditXPathOr 'EventID' @(4768, 4771, 4740, 4723, 4724, 4738)) + ")$tf] and EventData[Data[@Name='TargetSid']='$sid']]" }
                    foreach ($n in @($Target.KerberosVariants)) {
                        $selects += @{ Path = 'Security'; Query = "*[System[(EventID=4769)$tf] and EventData[Data[@Name='TargetUserName']='$n']]" }
                    }
                }
                $res.Preconditions['QuerySelects'] = @($selects).Count
                [void]$res.Notes.Add('XPath name match is case-sensitive; variants used: ' + (@($Target.NameVariants) -join ', '))

                $info = Get-AuditLogInfo -ComputerName $ComputerName -LogName 'Security'
                $res.Preconditions['LogMode'] = $info.LogMode
                $res.Preconditions['LogMaxSizeBytes'] = $info.MaximumSize
                $res.Preconditions['LogFileSizeBytes'] = $info.FileSize
                $res.Preconditions['LogRecordCount'] = $info.RecordCount
                $res.Preconditions['LogOldest'] = $info.Oldest
                Write-AuditRemoteLog $res 'Verbose' ('Security log: mode ' + $info.LogMode + ', ' + $info.RecordCount + ' records, ' + $info.FileSize + ' of ' + $info.MaximumSize + ' bytes, oldest ' + $info.Oldest) $Options

                $filterXml = New-AuditQueryList $selects
                Write-AuditRemoteLog $res 'Debug' ('FilterXml: ' + $filterXml) $Options
                $events = Invoke-AuditWinEvent -ComputerName $ComputerName -FilterXml $filterXml -MaxEvents $max
                $seen = @{}
                foreach ($e in $events) {
                    $k = [string]$e.RecordId
                    if ($seen.ContainsKey($k)) { continue }
                    $seen[$k] = $true
                    [void]$res.Records.Add($e)
                }
                $res.WindowStart = $info.Oldest
                if ($max -gt 0 -and @($events).Count -ge $max) {
                    # Neueste zuerst - bei Abschneiden beginnt das belastbare Fenster beim aeltesten gelieferten Ereignis
                    $res.Truncated = $true
                    $oldest = $null
                    foreach ($e in $events) { if ($null -eq $oldest -or $e.TimeCreated -lt $oldest) { $oldest = $e.TimeCreated } }
                    $res.WindowStart = $oldest
                    Write-AuditRemoteLog $res 'Warning' ('MaxEventsPerQuery (' + $max + ') reached - window shortened to ' + $oldest) $Options
                }
                $res.WindowEnd = ConvertTo-AuditRemoteIso (Get-Date)
                Write-AuditRemoteLog $res 'Verbose' ('Matching security events: ' + $res.Records.Count) $Options

                # Wurde das Log geleert? (1102)
                try {
                    $cleared = Invoke-AuditWinEvent -ComputerName $ComputerName -MaxEvents 1 -FilterXml (New-AuditQueryList @(@{ Path = 'Security'; Query = '*[System[(EventID=1102)]]' }))
                    if (@($cleared).Count -gt 0) {
                        $c = @($cleared)[0]
                        $res.Preconditions['LastCleared'] = $c.TimeCreated
                        $res.Preconditions['LastClearedBy'] = [string]$c.SubjectDomainName + '\' + [string]$c.SubjectUserName
                        Write-AuditRemoteLog $res 'Warning' ('Security log was cleared at ' + $c.TimeCreated + ' by ' + $res.Preconditions['LastClearedBy']) $Options
                    }
                }
                catch { $res.Preconditions['LastCleared'] = 'unknown: ' + $_.Exception.Message }

                # Effektive Audit-Policy - nur lokal auf dem Zielhost moeglich (WinRM), nicht per RPC
                if ($ComputerName) {
                    $res.Preconditions['AuditPolicy'] = 'unknown (RPC transport)'
                }
                else {
                    try {
                        $wanted = @{
                            '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'Logon'
                            '{0CCE9216-69AE-11D9-BED3-505054503030}' = 'Logoff'
                            '{0CCE921B-69AE-11D9-BED3-505054503030}' = 'SpecialLogon'
                            '{0CCE9217-69AE-11D9-BED3-505054503030}' = 'AccountLockout'
                            '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'CredentialValidation'
                            '{0CCE9242-69AE-11D9-BED3-505054503030}' = 'KerberosAuthenticationService'
                            '{0CCE9240-69AE-11D9-BED3-505054503030}' = 'KerberosServiceTicketOperations'
                            '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'UserAccountManagement'
                        }
                        $policy = @{}
                        foreach ($line in @(& auditpol.exe /get /category:* /r 2>$null)) {
                            $fields = ([string]$line).Split(',')
                            for ($i = 0; $i -lt $fields.Length - 1; $i++) {
                                $g = $fields[$i].Trim().ToUpper()
                                if ($wanted.ContainsKey($g)) {
                                    $raw = $fields[$i + 1].Trim()
                                    $policy[$wanted[$g]] = @{
                                        Raw     = $raw
                                        Success = [bool]($raw -match 'Success|Erfolg')
                                        Failure = [bool]($raw -match 'Failure|Fehler')
                                    }
                                }
                            }
                        }
                        if ($policy.Count -eq 0) {
                            $res.Preconditions['AuditPolicy'] = 'unknown (auditpol returned no data)'
                            Write-AuditRemoteLog $res 'Warning' 'auditpol returned no data (not elevated?)' $Options
                        }
                        else {
                            $res.Preconditions['AuditPolicy'] = $policy
                            foreach ($k in $policy.Keys) {
                                if (-not $policy[$k].Success) { Write-AuditRemoteLog $res 'Warning' ('Audit policy: success auditing is OFF for ' + $k + ' (' + $policy[$k].Raw + ')') $Options }
                                else { Write-AuditRemoteLog $res 'Debug' ('Audit policy ' + $k + ': ' + $policy[$k].Raw) $Options }
                            }
                        }
                    }
                    catch { $res.Preconditions['AuditPolicy'] = 'unknown: ' + $_.Exception.Message }
                }
                $res
            }
        }

        # ------------------------------------------------------------------ TerminalServices (Gegenprobe)
        @{
            Name       = 'TerminalServicesLog'
            Role       = 'CrossCheck'
            Scope      = 'Host'
            Transports = @('WinRM', 'Rpc')
            Script     = {
                param($ComputerName, $Target, $Options)
                $res = New-AuditRemoteResult
                $max = [int]$Options.MaxEventsPerQuery
                $tf = Get-AuditTimeFilter ([int]$Options.LookbackDays)
                $logs = @(
                    @{ Name = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Ids = @(21, 22, 23, 24, 25); Primary = $true }
                    @{ Name = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149); Primary = $false }
                )
                $found = 0
                $scanned = 0
                foreach ($l in $logs) {
                    try { $info = Get-AuditLogInfo -ComputerName $ComputerName -LogName $l.Name }
                    catch {
                        if ((Get-AuditErrorKind $_) -eq 'NotSupported') {
                            [void]$res.Notes.Add('log not present: ' + $l.Name)
                            Write-AuditRemoteLog $res 'Verbose' ('Log not present: ' + $l.Name) $Options
                            continue
                        }
                        throw
                    }
                    $found++
                    $res.Preconditions[$l.Name] = @{ Oldest = $info.Oldest; RecordCount = $info.RecordCount; IsEnabled = $info.IsEnabled }
                    if ($l.Primary) { $res.WindowStart = $info.Oldest }
                    $q = New-AuditQueryList @(@{ Path = $l.Name; Query = "*[System[(" + (New-AuditXPathOr 'EventID' $l.Ids) + ")$tf]]" })
                    $events = Invoke-AuditWinEvent -ComputerName $ComputerName -FilterXml $q -MaxEvents $max
                    if ($max -gt 0 -and @($events).Count -ge $max) { $res.Truncated = $true }
                    foreach ($e in $events) {
                        $scanned++
                        # Kontofilter case-insensitiv hier statt im XPath (Logs sind klein)
                        if ($e.ContainsKey('Param1')) { $user = [string]$e.Param1; $dom = [string]$e.Param2 }
                        else {
                            $u = [string]$e.User; $dom = ''; $user = $u
                            if ($u.Contains('\')) { $dom = $u.Split('\')[0]; $user = $u.Split('\')[1] }
                        }
                        if ($user -ieq $Target.SamAccountName) {
                            $e['AuditUserName'] = $user
                            $e['AuditUserDomain'] = $dom
                            [void]$res.Records.Add($e)
                        }
                    }
                }
                if ($found -eq 0) { throw 'AUDIT_NOTSUPPORTED: no TerminalServices operational logs on this host' }
                $res.Preconditions['EventsScanned'] = $scanned
                Write-AuditRemoteLog $res 'Verbose' ('TerminalServices logs: ' + $scanned + ' events scanned, ' + $res.Records.Count + ' for the target account') $Options
                $res.WindowEnd = ConvertTo-AuditRemoteIso (Get-Date)
                $res
            }
        }

        # ------------------------------------------------------------------ Winlogon im System-Log (Gegenprobe)
        @{
            Name       = 'WinlogonSystemLog'
            Role       = 'CrossCheck'
            Scope      = 'Host'
            Transports = @('WinRM', 'Rpc')
            Script     = {
                param($ComputerName, $Target, $Options)
                $res = New-AuditRemoteResult
                $tf = Get-AuditTimeFilter ([int]$Options.LookbackDays)
                $sid = $Target.Sid
                $info = Get-AuditLogInfo -ComputerName $ComputerName -LogName 'System'
                $res.Preconditions['LogOldest'] = $info.Oldest
                $res.Preconditions['LogRecordCount'] = $info.RecordCount
                $q = New-AuditQueryList @(
                    @{ Path = 'System'; Query = "*[System[Provider[@Name='Microsoft-Windows-Winlogon'] and (EventID=7001 or EventID=7002)$tf] and EventData[Data[@Name='UserSid']='$sid']]" }
                    @{ Path = 'System'; Query = "*[System[Provider[@Name='Microsoft-Windows-Winlogon'] and (EventID=7001 or EventID=7002)$tf and Security[@UserID='$sid']]]" }
                )
                $events = Invoke-AuditWinEvent -ComputerName $ComputerName -FilterXml $q -MaxEvents ([int]$Options.MaxEventsPerQuery)
                $seen = @{}
                foreach ($e in $events) {
                    if ($seen.ContainsKey([string]$e.RecordId)) { continue }
                    $seen[[string]$e.RecordId] = $true
                    [void]$res.Records.Add($e)
                }
                $res.WindowStart = $info.Oldest
                $res.WindowEnd = ConvertTo-AuditRemoteIso (Get-Date)
                Write-AuditRemoteLog $res 'Verbose' ('Winlogon 7001/7002: ' + $res.Records.Count + ' events, system log oldest ' + $info.Oldest) $Options
                $res
            }
        }

        # ------------------------------------------------------------------ Profil in der Registry (Gegenprobe)
        @{
            Name       = 'ProfileList'
            Role       = 'CrossCheck'
            Scope      = 'Host'
            Transports = @('WinRM', 'Rpc')
            Script     = {
                param($ComputerName, $Target, $Options)
                $res = New-AuditRemoteResult
                if ($ComputerName) { $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName) }
                else { $base = [Microsoft.Win32.Registry]::LocalMachine }
                try {
                    $pl = $base.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList')
                    if ($null -eq $pl) { throw 'AUDIT_NOTSUPPORTED: ProfileList key not readable' }
                    $mask = [int64]4294967295
                    foreach ($keyName in @($Target.Sid, ($Target.Sid + '.bak'))) {
                        $k = $pl.OpenSubKey($keyName)
                        if ($null -eq $k) { continue }
                        $rec = @{ KeyName = $keyName; IsBak = $keyName.EndsWith('.bak') }
                        $rec['ProfileImagePath'] = [string]$k.GetValue('ProfileImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        $rec['State'] = $k.GetValue('State')
                        foreach ($pair in @(@('LocalProfileLoadTime', 'LoadTime'), @('LocalProfileUnloadTime', 'UnloadTime'))) {
                            $hi = $k.GetValue($pair[0] + 'High'); $lo = $k.GetValue($pair[0] + 'Low')
                            $rec[$pair[1]] = $null
                            if ($null -ne $hi -and $null -ne $lo) {
                                $ft = (([int64]$hi -band $mask) * 4294967296) + ([int64]$lo -band $mask)
                                if ($ft -gt 0) { $rec[$pair[1]] = ConvertTo-AuditRemoteIso ([datetime]::FromFileTimeUtc($ft)) }
                            }
                        }
                        # NTUSER.DAT-Aenderung als zweiter Zeitstempel (bei 2008 ohne LoadTime-Werte der einzige)
                        $rec['NtUserDatLastWrite'] = $null
                        try {
                            $p = $rec['ProfileImagePath'] -replace '%SystemDrive%', 'C:'
                            if ($ComputerName -and $p -match '^([A-Za-z]):\\(.*)$') { $p = '\\' + $ComputerName + '\' + $matches[1] + '$\' + $matches[2] }
                            $f = Get-Item -LiteralPath (Join-Path $p 'NTUSER.DAT') -Force -ErrorAction Stop
                            $rec['NtUserDatLastWrite'] = ConvertTo-AuditRemoteIso $f.LastWriteTimeUtc
                        }
                        catch {
                            $rec['NtUserDatError'] = $_.Exception.Message
                            Write-AuditRemoteLog $res 'Verbose' ('NTUSER.DAT not readable: ' + $_.Exception.Message) $Options
                        }
                        Write-AuditRemoteLog $res 'Verbose' ('Profile key ' + $keyName + ': ' + $rec['ProfileImagePath'] + ', loaded ' + $rec['LoadTime']) $Options
                        [void]$res.Records.Add($rec)
                        $k.Close()
                    }
                    $pl.Close()
                    if ($res.Records.Count -eq 0) { Write-AuditRemoteLog $res 'Verbose' 'No profile for the target account on this host' $Options }
                }
                finally { if ($ComputerName) { $base.Close() } }
                $res.WindowEnd = ConvertTo-AuditRemoteIso (Get-Date)
                $res
            }
        }

        # ------------------------------------------------------------------ AD-Attribute je DC (Gegenprobe)
        @{
            Name       = 'ADAttributes'
            Role       = 'CrossCheck'
            Scope      = 'DomainController'
            Transports = @('Ldap')
            Script     = {
                param($ComputerName, $Target, $Options)
                $res = New-AuditRemoteResult
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Target.Sid)
                $bytes = New-Object byte[] $sidObj.BinaryLength
                $sidObj.GetBinaryForm($bytes, 0)
                $sidFilter = ''
                foreach ($b in $bytes) { $sidFilter += ('\{0:x2}' -f $b) }

                $root = New-Object System.DirectoryServices.DirectoryEntry('LDAP://' + $ComputerName + '/' + $Target.DomainDn)
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
                $searcher.Filter = '(objectSid=' + $sidFilter + ')'
                $props = @('sAMAccountName', 'distinguishedName', 'lastLogon', 'logonCount', 'badPwdCount', 'badPasswordTime',
                           'lastLogonTimestamp', 'pwdLastSet', 'whenChanged', 'whenCreated', 'lockoutTime', 'userAccountControl',
                           'adminCount', 'servicePrincipalName', 'msDS-SupportedEncryptionTypes')
                foreach ($p in $props) { [void]$searcher.PropertiesToLoad.Add($p) }
                $r = $searcher.FindOne()
                if ($null -eq $r) { throw "Account $($Target.Sid) not found on $ComputerName" }

                $rec = @{ DomainController = $ComputerName }
                foreach ($p in $props) {
                    $vals = @($r.Properties[$p.ToLowerInvariant()])
                    if ($vals.Count -eq 0) { $rec[$p] = $null; continue }
                    $conv = @()
                    foreach ($v in $vals) {
                        if ($v -is [datetime]) { $conv += ConvertTo-AuditRemoteIso ([datetime]::SpecifyKind($v, [System.DateTimeKind]::Utc)) }
                        else { $conv += [string]$v }
                    }
                    if ($p -eq 'servicePrincipalName') { $rec[$p] = $conv } else { $rec[$p] = $conv[0] }
                }

                # Replikationsmetadaten von pwdLastSet: Version = Anzahl Passwortaenderungen, Ursprungs-DC
                try {
                    $entry = $r.GetDirectoryEntry()
                    $entry.RefreshCache(@('msDS-ReplAttributeMetaData'))
                    foreach ($xmlText in @($entry.Properties['msDS-ReplAttributeMetaData'])) {
                        $x = [xml]([string]$xmlText -replace '\x00', '')
                        $m = $x.DS_REPL_ATTR_META_DATA
                        if ($m -and $m.pszAttributeName -eq 'pwdLastSet') {
                            $rec['PwdLastSetVersion'] = [string]$m.dwVersion
                            $rec['PwdLastSetOriginatingTime'] = [string]$m.ftimeLastOriginatingChange
                            $rec['PwdLastSetOriginatingDsa'] = [string]$m.pszLastOriginatingDsaDN
                        }
                    }
                }
                catch { [void]$res.Notes.Add('msDS-ReplAttributeMetaData: ' + $_.Exception.Message) }

                try {
                    $rec['LogonTimeSyncIntervalDays'] = $null
                    $v = $root.Properties['msDS-LogonTimeSyncInterval'].Value
                    if ($null -ne $v) { $rec['LogonTimeSyncIntervalDays'] = [int]$v }
                }
                catch { }

                [void]$res.Records.Add($rec)
                Write-AuditRemoteLog $res 'Verbose' ('lastLogon=' + $rec['lastLogon'] + ' logonCount=' + $rec['logonCount'] + ' badPasswordTime=' + $rec['badPasswordTime'] + ' pwdLastSet=' + $rec['pwdLastSet']) $Options
                $res.WindowEnd = ConvertTo-AuditRemoteIso (Get-Date)
                $res
            }
        }
    )

    # ====================================================================== Analyse (lokal)
    Analyze = {
        param($Context, $MethodResults, $Target, $Options, $Hosts)

        $tolX = [int](Get-AuditProperty $Options 'CrossCheckToleranceSeconds' 120)
        $tolDc = [int](Get-AuditProperty $Options 'DcAttributeToleranceSeconds' 300)
        $tolProfile = [int](Get-AuditProperty $Options 'ProfileToleranceSeconds' 300)
        $samples = [int](Get-AuditProperty $Options 'EvidenceSamples' 5)
        $includeLocal = [bool](Get-AuditProperty $Options 'IncludeLocalAdministrator' $false)
        $out = New-Object System.Collections.ArrayList

        $hostIndex = @{}
        foreach ($h in @($Hosts)) { $hostIndex[$h.Name.ToLowerInvariant()] = $h }

        function Get-MethodResult([string]$HostName, [string]$Method) {
            $MethodResults | Where-Object { $_.Host -eq $HostName -and $_.Method -eq $Method } | Select-Object -First 1
        }
        function Get-Window($r) {
            if ($null -eq $r -or $r.Status -ne 'Ok' -or $null -eq $r.Result) { return $null }
            @{ Start = ConvertFrom-AuditTimeString $r.Result.WindowStart; End = ConvertFrom-AuditTimeString $r.Result.WindowEnd }
        }
        function Get-MethodLabel($r) { '{0} ({1})' -f $r.Method, $r.Transport }
        function Get-Clean([object]$v) {
            $s = ([string]$v).Trim()
            if ($s -eq '-') { return '' }
            $s -replace '^::ffff:', ''
        }
        function Get-Categories {
            @{
                4624 = @('Logon', 'LogonEvent');           4625 = @('LogonFailed', 'LogonEvent')
                4634 = @('Logoff', 'LogonEvent');          4647 = @('Logoff', 'LogonEvent')
                4648 = @('ExplicitCredentials', 'LogonEvent'); 4672 = @('SpecialPrivileges', 'LogonEvent')
                4768 = @('KerberosTGT', 'DcAuthEvent');    4769 = @('KerberosTGS', 'DcAuthEvent')
                4771 = @('KerberosPreAuthFailed', 'DcAuthEvent'); 4776 = @('NtlmValidation', 'DcAuthEvent')
                4740 = @('Lockout', 'AccountEvent');       4723 = @('PasswordChange', 'AccountEvent')
                4724 = @('PasswordReset', 'AccountEvent'); 4738 = @('AccountChanged', 'AccountEvent')
            }
        }
        $categories = Get-Categories

        # ------------------------------------------------ Security-Ereignis -> Beobachtung
        function ConvertTo-Observation($rec, $hi) {
            $id = [int]$rec.EventId
            if (-not $categories.ContainsKey($id)) { return $null }
            $role = 'Target'
            $match = $null
            switch ($id) {
                { $_ -in 4672 } {
                    $role = 'Subject'
                    $match = Resolve-AuditAccountMatch -Target $Target -Sid $rec.SubjectUserSid -Name $rec.SubjectUserName -Domain $rec.SubjectDomainName -HostShortName $hi.ShortName -IsDomainController $hi.IsDomainController
                }
                { $_ -in 4648 } {
                    # Wurden die Anmeldedaten des Zielkontos explizit verwendet (runas, Laufwerk, Task)?
                    $match = Resolve-AuditAccountMatch -Target $Target -Name $rec.TargetUserName -Domain $rec.TargetDomainName -HostShortName $hi.ShortName -IsDomainController $hi.IsDomainController
                    $role = 'CredentialsUsed'
                    if (-not $match) {
                        $role = 'Subject'
                        $match = Resolve-AuditAccountMatch -Target $Target -Sid $rec.SubjectUserSid -Name $rec.SubjectUserName -Domain $rec.SubjectDomainName -HostShortName $hi.ShortName -IsDomainController $hi.IsDomainController
                    }
                }
                { $_ -in 4768, 4771, 4740, 4723, 4724, 4738 } {
                    $match = Resolve-AuditAccountMatch -Target $Target -Sid $rec.TargetSid -Name $rec.TargetUserName -Domain $rec.TargetDomainName -HostShortName $hi.ShortName -IsDomainController $true
                }
                4769 {
                    $match = Resolve-AuditAccountMatch -Target $Target -Name $rec.TargetUserName -Domain $rec.TargetDomainName -HostShortName $hi.ShortName -IsDomainController $true
                }
                4776 {
                    if ($hi.IsDomainController) {
                        $match = Resolve-AuditAccountMatch -Target $Target -Name $rec.TargetUserName -HostShortName $hi.ShortName -IsDomainController $true
                    }
                    elseif ([string]$rec.TargetUserName -ieq $Target.SamAccountName) {
                        # 4776 auf einem Member-Server = Pruefung gegen die lokale SAM
                        $match = @{ Scope = 'Local'; Match = 'Name'; Display = $hi.ShortName + '\' + $rec.TargetUserName }
                    }
                }
                default {
                    $match = Resolve-AuditAccountMatch -Target $Target -Sid $rec.TargetUserSid -Name $rec.TargetUserName -Domain $rec.TargetDomainName -HostShortName $hi.ShortName -IsDomainController $hi.IsDomainController
                }
            }
            if (-not $match) { return $null }

            $status = ''
            foreach ($f in @('Status', 'FailureCode')) { if ($rec[$f] -and -not $status) { $status = [string]$rec[$f] } }
            if ($rec['SubStatus'] -and $rec['SubStatus'] -ne '0x0') { $status = $status + '/' + $rec['SubStatus'] }
            $success = [bool]$rec.AuditSuccess
            if ($id -in 4625, 4771) { $success = $false }
            elseif ($id -in 4768, 4769, 4776) { $success = ([string]$rec.Status -eq '0x0') }

            $lt = $null
            if ($rec['LogonType']) { $lt = [int]$rec['LogonType'] }
            $logonId = [string]$rec['TargetLogonId']
            if ($id -eq 4672) { $logonId = [string]$rec['SubjectLogonId'] }

            $raw = ''
            if ($rec['TargetUserName']) { $raw = [string]$rec['TargetUserName']; if ($rec['TargetDomainName']) { $raw = [string]$rec['TargetDomainName'] + '\' + $raw } }
            if ($role -eq 'Subject' -and $rec['SubjectUserName']) { $raw = [string]$rec['SubjectDomainName'] + '\' + [string]$rec['SubjectUserName'] }
            if (-not $raw) { $raw = $match.Display }
            $ws = $(if ($rec['WorkstationName']) { $rec['WorkstationName'] } else { $rec['Workstation'] })
            if ($id -eq 4740) {
                # 4740 fuehrt den aufrufenden Computer in TargetDomainName
                $ws = $rec['TargetDomainName']; $raw = $match.Display
            }

            @{
                Time         = ConvertFrom-AuditTimeString $rec.TimeCreated
                EventId      = $id
                Category     = $categories[$id][0]
                ObjectType   = $categories[$id][1]
                LogonType    = $lt
                LogonId      = $logonId
                SourceIp     = Get-Clean $rec['IpAddress']
                Workstation  = Get-Clean $ws
                AuthPackage  = [string]$rec['AuthenticationPackageName']
                LogonProcess = ([string]$rec['LogonProcessName']).Trim()
                ProcessName  = Get-Clean $rec['ProcessName']
                TargetServer = Get-Clean $rec['TargetServerName']
                ServiceName  = [string]$rec['ServiceName']
                Status       = $status
                Success      = $success
                Role         = $role
                Match        = $match
                RawAccount   = $raw
                Record       = $rec
                RecordId     = [int64]$rec.RecordId
                Privileged   = $false
                States       = New-Object System.Collections.ArrayList
                Matches      = New-Object System.Collections.ArrayList
            }
        }

        function ConvertTo-SessionObservation($rec, $hi, [string]$kind) {
            $id = [int]$rec.EventId
            if ($kind -eq 'Winlogon') {
                # UserSid aus EventData (oder, falls dort leer, aus System/Security@UserID)
                $sid = [string]$rec['UserSid']; if (-not $sid) { $sid = [string]$rec['SystemUserSid'] }
                $match = Resolve-AuditAccountMatch -Target $Target -Sid $sid -HostShortName $hi.ShortName -IsDomainController $hi.IsDomainController
                $addr = ''; $session = [string]$rec['TSId']
            }
            else {
                $match = Resolve-AuditAccountMatch -Target $Target -Name $rec.AuditUserName -Domain $rec.AuditUserDomain -HostShortName $hi.ShortName -IsDomainController $hi.IsDomainController
                $addr = Get-Clean $(if ($rec['Address']) { $rec['Address'] } else { $rec['Param3'] })
                $session = [string]$rec['SessionID']
            }
            if (-not $match) { return $null }
            $source = switch ($id) { 1149 { 'RCM' } { $_ -in 7001, 7002 } { 'Winlogon' } default { 'LSM' } }
            @{
                Time = ConvertFrom-AuditTimeString $rec.TimeCreated; EventId = $id; Source = $source
                Address = $addr; SessionId = $session; Match = $match; Record = $rec; RecordId = [int64]$rec.RecordId
                RawAccount = $(if ($rec['AuditUserName']) { ([string]$rec['AuditUserDomain'] + '\' + [string]$rec['AuditUserName']).TrimStart('\') } else { $match.Display })
            }
        }

        function Add-Evidence($list, $obs, [string]$method, [string]$role, [string]$hostName, [string]$transport) {
            [void]$list.Add((New-AuditEvidence -Method $method -Role $role -HostName $hostName -Transport $transport -Record $obs.Record))
        }

        function Get-SampleIndex([int]$count) {
            if ($count -le (2 * $samples)) { return @(0..($count - 1)) }
            @(0..($samples - 1)) + @(($count - $samples)..($count - 1))
        }

        $hostNames = @($MethodResults | ForEach-Object { $_.Host } | Sort-Object -Unique)
        $dcData = @{}

        foreach ($hn in $hostNames) {
            $hi = $hostIndex[$hn.ToLowerInvariant()]
            if (-not $hi) { $hi = New-AuditHostInfo -Name $hn }
            $sec = Get-MethodResult $hn 'SecurityLog'
            $ts = Get-MethodResult $hn 'TerminalServicesLog'
            $wl = Get-MethodResult $hn 'WinlogonSystemLog'
            $pl = Get-MethodResult $hn 'ProfileList'
            $secWindow = Get-Window $sec

            # ---------------------------------------- Primaerbeobachtungen
            $obs = New-Object System.Collections.ArrayList
            $localIgnored = 0
            if ($secWindow) {
                $seen = @{}
                foreach ($rec in @($sec.Result.Records)) {
                    if ($seen.ContainsKey([string]$rec.RecordId)) { continue }
                    $seen[[string]$rec.RecordId] = $true
                    $o = ConvertTo-Observation $rec $hi
                    if (-not $o) { continue }
                    if ($o.Match.Scope -eq 'Local' -and -not $includeLocal) { $localIgnored++; continue }
                    [void]$obs.Add($o)
                }
            }

            # 4672 an die zugehoerige 4624 haengen (gleiche LogonId, wenige Sekunden)
            $byLogonId = @{}
            foreach ($o in $obs) { if ($o.EventId -eq 4624 -and $o.LogonId) { $byLogonId[$o.LogonId] = @($byLogonId[$o.LogonId]) + @($o) } }
            $consumed = @{}
            foreach ($o in @($obs | Where-Object { $_.EventId -eq 4672 })) {
                foreach ($c in @($byLogonId[$o.LogonId])) {
                    if ($c -and [math]::Abs(($c.Time - $o.Time).TotalSeconds) -le 5) { $c.Privileged = $true; [void]$c.Matches.Add(@{ Method = 'SecurityLog'; Obs = $o }); $consumed[$o.RecordId] = $true; break }
                }
            }
            $obs = @($obs | Where-Object { -not $consumed.ContainsKey($_.RecordId) })

            # ---------------------------------------- Gegenprobe interaktive Anmeldungen
            $sessionObs = @{ LSM = @(); RCM = @(); Winlogon = @() }
            $tsWindow = Get-Window $ts
            $wlWindow = Get-Window $wl
            if ($tsWindow) {
                foreach ($rec in @($ts.Result.Records)) {
                    $s = ConvertTo-SessionObservation $rec $hi 'TS'
                    if ($s -and ($includeLocal -or $s.Match.Scope -ne 'Local')) { $sessionObs[$s.Source] += @($s) }
                }
            }
            if ($wlWindow) {
                foreach ($rec in @($wl.Result.Records)) {
                    $s = ConvertTo-SessionObservation $rec $hi 'Winlogon'
                    if ($s -and ($includeLocal -or $s.Match.Scope -ne 'Local')) { $sessionObs['Winlogon'] += @($s) }
                }
            }

            $interactive = @($obs | Where-Object { $_.EventId -eq 4624 -and $_.LogonType -in 2, 7, 10, 11 })
            $checks = @(
                @{ Source = 'LSM'; Result = $ts; Window = $tsWindow; Ids = @(21, 25)
                   Needs = { param($p) $p.LogonType -in 2, 10, 11 }
                   Can = { param($p, $s) $p.Match.Scope -eq $s.Match.Scope -and ($p.LogonType -in 2, 10, 11 -or ($p.LogonType -eq 7 -and $s.EventId -eq 25)) } }
                @{ Source = 'RCM'; Result = $ts; Window = $tsWindow; Ids = @(1149)
                   Needs = { param($p) $false }
                   Can = { param($p, $s) $p.Match.Scope -eq $s.Match.Scope -and $p.LogonType -eq 10 } }
                @{ Source = 'Winlogon'; Result = $wl; Window = $wlWindow; Ids = @(7001)
                   Needs = { param($p) $p.LogonType -in 2, 10, 11 }
                   Can = { param($p, $s) $p.Match.Scope -eq $s.Match.Scope -and $p.LogonType -in 2, 10, 11 } }
            )
            $secondaryLeftovers = New-Object System.Collections.ArrayList
            foreach ($chk in $checks) {
                $sec2 = @($sessionObs[$chk.Source] | Where-Object { $_.EventId -in $chk.Ids })
                $cmp = Compare-AuditTimeline -Primary $interactive -Secondary $sec2 -PrimaryWindow $secWindow `
                    -SecondaryWindow $chk.Window -ToleranceSeconds $tolX -NeedsMatch $chk.Needs -CanMatch $chk.Can
                foreach ($p in $cmp.Primary) {
                    if ($p.State -ne 'NotChecked' -or $p.Match) { [void]$p.Item.States.Add($p.State) }
                    if ($p.Match) { [void]$p.Item.Matches.Add(@{ Method = $chk.Result.Method; Transport = $chk.Result.Transport; Obs = $p.Match }) }
                }
                foreach ($s in $cmp.Secondary) {
                    if ($s.State -ne 'Confirmed') { [void]$secondaryLeftovers.Add(@{ Obs = $s.Item; State = $s.State; Result = $chk.Result }) }
                }
            }
            # Reine Sitzungsereignisse (Abmeldung/Trennung) - Kontext ohne eigene Gegenprobe
            foreach ($s in @($sessionObs['LSM'] | Where-Object { $_.EventId -in 23, 24 }) + @($sessionObs['Winlogon'] | Where-Object { $_.EventId -eq 7002 })) {
                $r = if ($s.Source -eq 'Winlogon') { $wl } else { $ts }
                [void]$secondaryLeftovers.Add(@{ Obs = $s; State = 'NotChecked'; Result = $r })
            }

            # ---------------------------------------- Aggregation Security-Ereignisse
            $groups = @{}
            foreach ($o in $obs) {
                $key = ($o.EventId, $o.LogonType, $o.SourceIp, $o.Workstation, $o.Role, $o.Status, $o.ServiceName, $o.TargetServer, $o.Match.Scope, $o.Match.Match) -join '|'
                if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.ArrayList }
                [void]$groups[$key].Add($o)
            }
            foreach ($key in $groups.Keys) {
                $items = @($groups[$key] | Sort-Object { $_.Time })
                $first = $items[0]; $last = $items[-1]
                $states = @()
                foreach ($i in $items) { if ($i.States.Count -gt 0) { $states += (Merge-AuditCrossCheckState -States @($i.States)) } else { $states += 'NotChecked' } }
                $cc = Merge-AuditCrossCheckState -States $states
                $counts = @{}
                foreach ($s in $states) { $counts[$s] = 1 + [int]$counts[$s] }
                if (@($states | Where-Object { $_ -ne 'NotChecked' }).Count -eq 0) {
                    $noteKey = 'Note.Logon.NoSecondSource'; $noteArgs = @()
                    if ($first.EventId -eq 4624 -and $first.LogonType -in 2, 10, 11) { $noteKey = 'Note.Logon.OutsideSecondaryWindow' }
                }
                else {
                    $noteKey = 'Note.Logon.Counts'
                    $noteArgs = @([int]$counts['Confirmed'], [int]$counts['OnlyPrimary'], [int]$counts['Unverifiable'], [int]$counts['NotChecked'], [int]$counts['Partial'])
                }
                $evidence = New-Object System.Collections.ArrayList
                foreach ($idx in (Get-SampleIndex $items.Count)) {
                    $i = $items[$idx]
                    Add-Evidence $evidence $i $sec.Method 'Primary' $hn $sec.Transport
                    foreach ($m in $i.Matches) { Add-Evidence $evidence $m.Obs $(if ($m.Method) { $m.Method } else { 'SecurityLog' }) 'CrossCheck' $hn $(if ($m.Transport) { $m.Transport } else { $sec.Transport }) }
                }
                $ltName = if ($null -ne $first.LogonType) { '@LogonType.' + $first.LogonType } else { '' }
                $attrs = @{
                    EventId = $first.EventId; Category = $first.Category; LogonType = $first.LogonType
                    SourceIp = $first.SourceIp; Workstation = $first.Workstation; Role = $first.Role
                    AuthPackage = (@($items | ForEach-Object { $_.AuthPackage } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
                    LogonProcess = (@($items | ForEach-Object { $_.LogonProcess } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
                    ProcessName = (@($items | ForEach-Object { $_.ProcessName } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
                    TargetServer = $first.TargetServer; ServiceName = $first.ServiceName; Status = $first.Status
                    Success = $first.Success; Privileged = [bool](@($items | Where-Object { $_.Privileged }).Count -gt 0)
                    Count = $items.Count; FirstSeen = $first.Time; LastSeen = $last.Time
                    RecordIds = @($items | ForEach-Object { $_.RecordId }); CrossCheckCounts = $counts
                    LogWindowStart = $secWindow.Start; LogTruncated = [bool]$sec.Result.Truncated
                }
                $detailArgs = @($first.LogonType, $ltName, $first.SourceIp, $first.Workstation, $items.Count, $first.Time, $last.Time,
                                $first.Status, $first.ServiceName, $(if ($first.TargetServer) { $first.TargetServer } else { $first.ProcessName }))
                $detailKey = 'Detail.Event.' + $first.Category
                if ($first.Category -eq 'ExplicitCredentials' -and $first.Role -eq 'Subject') { $detailKey = 'Detail.Event.ExplicitCredentialsSubject' }
                $f = New-AuditFinding -Source 'Logon' -HostName $hn -Account $first.RawAccount -ObjectType $first.ObjectType `
                    -DetailKey $detailKey -DetailArgs $detailArgs -Timestamp $last.Time -Method (Get-MethodLabel $sec) -Context $Context `
                    -AccountSid $(if ($first.Match.Scope -eq 'Domain') { $Target.Sid } else { [string]$first.Record.TargetUserSid }) `
                    -AccountScope $first.Match.Scope -AccountMatch $first.Match.Match `
                    -CorrelationKey ($hn + '|Logon|' + $key) -CrossCheck $cc -CrossCheckNoteKey $noteKey -CrossCheckNoteArgs $noteArgs `
                    -Attributes $attrs -Evidence $evidence.ToArray()
                [void]$out.Add($f)
            }

            # ---------------------------------------- Aggregation Sitzungsereignisse ohne Security-Entsprechung
            $sg = @{}
            foreach ($l in $secondaryLeftovers) {
                $key = ($l.Obs.Source, $l.Obs.EventId, $l.Obs.Address, $l.State, $l.Obs.Match.Scope) -join '|'
                if (-not $sg.ContainsKey($key)) { $sg[$key] = New-Object System.Collections.ArrayList }
                [void]$sg[$key].Add($l)
            }
            foreach ($key in $sg.Keys) {
                $items = @($sg[$key] | Sort-Object { $_.Obs.Time })
                $first = $items[0]; $last = $items[-1]
                $evidence = New-Object System.Collections.ArrayList
                foreach ($idx in (Get-SampleIndex $items.Count)) { Add-Evidence $evidence $items[$idx].Obs $items[$idx].Result.Method 'CrossCheck' $hn $items[$idx].Result.Transport }
                $noteKey = switch ($first.State) {
                    'OnlySecondary' { 'Note.Session.NoSecurityEvent' }
                    'Unverifiable'  { 'Note.Session.SecurityUnavailable' }
                    default         { 'Note.Session.Context' }
                }
                $f = New-AuditFinding -Source 'Logon' -HostName $hn -Account $first.Obs.RawAccount -ObjectType 'SessionEvent' `
                    -DetailKey ('Detail.Session.' + $first.Obs.EventId) `
                    -DetailArgs @($first.Obs.Address, $items.Count, $first.Obs.Time, $last.Obs.Time, $first.Obs.SessionId) `
                    -Timestamp $last.Obs.Time -Method (Get-MethodLabel $first.Result) -Context $Context `
                    -AccountSid $(if ($first.Obs.Match.Scope -eq 'Domain') { $Target.Sid } else { '' }) `
                    -AccountScope $first.Obs.Match.Scope -AccountMatch $first.Obs.Match.Match `
                    -CorrelationKey ($hn + '|Session|' + $key) -CrossCheck $first.State -CrossCheckNoteKey $noteKey `
                    -Attributes @{
                        EventId = $first.Obs.EventId; SourceLog = $first.Obs.Source; SourceIp = $first.Obs.Address
                        Count = $items.Count; FirstSeen = $first.Obs.Time; LastSeen = $last.Obs.Time
                        RecordIds = @($items | ForEach-Object { $_.Obs.RecordId })
                    } -Evidence $evidence.ToArray()
                [void]$out.Add($f)
            }

            # ---------------------------------------- Profil vs. Anmeldeereignisse
            if ($pl -and $pl.Status -eq 'Ok') {
                $profileLogons = @($obs | Where-Object { $_.EventId -eq 4624 -and $_.LogonType -in 2, 4, 5, 10, 11 -and $_.Match.Scope -eq 'Domain' })
                $records = @($pl.Result.Records)
                foreach ($rec in $records) {
                    $load = ConvertFrom-AuditTimeString $rec.LoadTime
                    $ntuser = ConvertFrom-AuditTimeString $rec.NtUserDatLastWrite
                    $ref = if ($load) { $load } else { $ntuser }
                    if (-not $secWindow) { $state = 'Unverifiable'; $nk = 'Note.Profile.SecurityUnavailable'; $na = @() }
                    elseif (-not $ref) { $state = 'NotChecked'; $nk = 'Note.Profile.NoTime'; $na = @() }
                    elseif (@($profileLogons | Where-Object { [math]::Abs(($_.Time - $ref).TotalSeconds) -le $tolProfile }).Count -gt 0) {
                        $state = 'Confirmed'; $nk = 'Note.Profile.Match'; $na = @($ref)
                    }
                    elseif ($ref -lt $secWindow.Start) { $state = 'NotChecked'; $nk = 'Note.Profile.BeforeWindow'; $na = @($ref, $secWindow.Start) }
                    else { $state = 'OnlySecondary'; $nk = 'Note.Profile.NoEvent'; $na = @($ref) }
                    $ev = @(New-AuditEvidence -Method $pl.Method -Role 'CrossCheck' -HostName $hn -Transport $pl.Transport -Record $rec)
                    $f = New-AuditFinding -Source 'Logon' -HostName $hn -Account $Target.Display -ObjectType 'UserProfile' `
                        -DetailKey 'Detail.Profile.Present' -DetailArgs @($rec.ProfileImagePath, $load, $ntuser) `
                        -Timestamp $ref -Method (Get-MethodLabel $pl) -Context $Context -AccountSid $Target.Sid `
                        -AccountScope 'Domain' -AccountMatch 'Sid' -CorrelationKey ($hn + '|Profile|' + $rec.KeyName) `
                        -CrossCheck $state -CrossCheckNoteKey $nk -CrossCheckNoteArgs $na `
                        -Attributes @{ ProfileImagePath = $rec.ProfileImagePath; KeyName = $rec.KeyName; IsBak = [bool]$rec.IsBak
                                       State = $rec.State; LoadTime = $load; UnloadTime = (ConvertFrom-AuditTimeString $rec.UnloadTime)
                                       NtUserDatLastWrite = $ntuser; MatchingLogons = $profileLogons.Count } `
                        -Evidence $ev
                    [void]$out.Add($f)
                }
                $interactiveDomain = @($profileLogons | Where-Object { $_.LogonType -in 2, 10, 11 })
                if ($records.Count -eq 0 -and $interactiveDomain.Count -gt 0) {
                    $f = New-AuditFinding -Source 'Logon' -HostName $hn -Account $Target.Display -ObjectType 'UserProfile' `
                        -DetailKey 'Detail.Profile.Missing' -DetailArgs @($interactiveDomain.Count) `
                        -Timestamp ($interactiveDomain | Sort-Object { $_.Time } | Select-Object -Last 1).Time `
                        -Method (Get-MethodLabel $pl) -Context $Context -AccountSid $Target.Sid -AccountScope 'Domain' -AccountMatch 'Sid' `
                        -CorrelationKey ($hn + '|Profile|missing') -CrossCheck 'Conflict' -CrossCheckNoteKey 'Note.Profile.MissingButLogons' `
                        -CrossCheckNoteArgs @($interactiveDomain.Count) -Attributes @{ MatchingLogons = $interactiveDomain.Count }
                    [void]$out.Add($f)
                }
            }

            Write-AuditLog -Level Verbose -Component 'Logon/Analyze' -HostName $hn -Message ("{0} security observations, {1} local-account events ignored, {2} unmatched session events, security window from {3}" -f `
                $obs.Count, $localIgnored, $secondaryLeftovers.Count, $(if ($secWindow) { ConvertTo-AuditIsoString $secWindow.Start } else { 'unavailable' }))

            if ($hi.IsDomainController) {
                $dcData[$hn] = @{ Obs = $obs; Window = $secWindow; Ad = (Get-MethodResult $hn 'ADAttributes'); Sec = $sec }
            }
        }

        # ================================================ AD-Attribute je DC vs. Ereignisse dieses DCs
        $adRecords = @{}
        $anyDcFailed = $false
        foreach ($dc in $dcData.Keys) {
            $d = $dcData[$dc]
            $ad = $d.Ad
            if (-not $ad -or $ad.Status -ne 'Ok' -or @($ad.Result.Records).Count -eq 0) { $anyDcFailed = $true; continue }
            $rec = @($ad.Result.Records)[0]
            $adRecords[$dc] = $rec
            $domainObs = @($d.Obs | Where-Object { $_.Match.Scope -eq 'Domain' })
            $label = Get-MethodLabel $ad
            $ev = @(New-AuditEvidence -Method $ad.Method -Role 'CrossCheck' -HostName $dc -Transport $ad.Transport -Record $rec)

            $lastLogon = ConvertFrom-AuditFileTime $rec.lastLogon
            $okTimes = @($domainObs | Where-Object { $_.EventId -in 4768, 4776 -and $_.Success } | ForEach-Object { $_.Time })
            $cmp = Compare-AuditPointInTime -AttributeTime $lastLogon -EventTimes $okTimes -EventWindow $d.Window -ToleranceSeconds $tolDc
            [void]$out.Add((New-AuditFinding -Source 'Logon' -HostName $dc -Account $Target.Display -ObjectType 'ADAttribute' `
                -DetailKey 'Detail.AD.LastLogon' -DetailArgs @($dc, $(if ($lastLogon) { $lastLogon } else { '@Value.Never' }), $rec.logonCount) `
                -Timestamp $lastLogon -Method $label -Context $Context -AccountSid $Target.Sid -AccountScope 'Domain' -AccountMatch 'Sid' `
                -CorrelationKey ($dc + '|AD|lastLogon') -CrossCheck $cmp.State -CrossCheckNoteKey $cmp.NoteKey -CrossCheckNoteArgs $cmp.NoteArgs `
                -Attributes @{ Attribute = 'lastLogon'; Value = $lastLogon; LogonCount = $rec.logonCount; NewestEvent = $cmp.NewestEvent; ComparedEvents = $okTimes.Count } `
                -Evidence $ev))

            $badTime = ConvertFrom-AuditFileTime $rec.badPasswordTime
            $failTimes = @($domainObs | Where-Object { ($_.EventId -in 4771, 4625) -or ($_.EventId -eq 4776 -and -not $_.Success) } | ForEach-Object { $_.Time })
            $cmp = Compare-AuditPointInTime -AttributeTime $badTime -EventTimes $failTimes -EventWindow $d.Window -ToleranceSeconds $tolDc
            [void]$out.Add((New-AuditFinding -Source 'Logon' -HostName $dc -Account $Target.Display -ObjectType 'ADAttribute' `
                -DetailKey 'Detail.AD.BadPassword' -DetailArgs @($dc, $(if ($badTime) { $badTime } else { '@Value.Never' }), $rec.badPwdCount) `
                -Timestamp $badTime -Method $label -Context $Context -AccountSid $Target.Sid -AccountScope 'Domain' -AccountMatch 'Sid' `
                -CorrelationKey ($dc + '|AD|badPasswordTime') -CrossCheck $cmp.State -CrossCheckNoteKey $cmp.NoteKey -CrossCheckNoteArgs $cmp.NoteArgs `
                -Attributes @{ Attribute = 'badPasswordTime'; Value = $badTime; BadPwdCount = $rec.badPwdCount; NewestEvent = $cmp.NewestEvent; ComparedEvents = $failTimes.Count } `
                -Evidence $ev))
        }

        if ($adRecords.Count -gt 0) {
            $domainHost = $Target.DomainDns
            $allEv = @(foreach ($dc in $adRecords.Keys) { New-AuditEvidence -Method 'ADAttributes' -Role 'CrossCheck' -HostName $dc -Transport 'Ldap' -Record $adRecords[$dc] })
            $any = @($adRecords.Values)[0]

            # pwdLastSet: repliziert -> alle DCs muessen uebereinstimmen; zusaetzlich gegen 4723/4724
            $pwdValues = @{}
            foreach ($dc in $adRecords.Keys) { $pwdValues[$dc] = [string]$adRecords[$dc].pwdLastSet }
            $pwdLastSet = ConvertFrom-AuditFileTime $any.pwdLastSet
            $distinct = @($pwdValues.Values | Sort-Object -Unique)
            if ($distinct.Count -gt 1) {
                $state = 'Conflict'; $nk = 'Note.AD.PwdLastSetDiffers'
                $na = @((@($pwdValues.Keys | ForEach-Object { '{0}={1}' -f $_, (ConvertFrom-AuditFileTime $pwdValues[$_]) }) -join '; '))
            }
            else {
                $pwdTimes = @(foreach ($dc in $dcData.Keys) { $dcData[$dc].Obs | Where-Object { $_.EventId -in 4723, 4724 -and $_.Success } | ForEach-Object { $_.Time } })
                $windows = @(foreach ($dc in $dcData.Keys) { $dcData[$dc].Window })
                $win = $null
                if (@($windows | Where-Object { $null -eq $_ }).Count -eq 0 -and $windows.Count -gt 0) {
                    # Gemeinsames Fenster: erst ab dem Zeitpunkt, ab dem ALLE DCs Logs haben
                    $win = @{ Start = ($windows | ForEach-Object { $_.Start } | Measure-Object -Maximum).Maximum; End = Get-AuditUtcNow }
                }
                $cmp = Compare-AuditPointInTime -AttributeTime $pwdLastSet -EventTimes $pwdTimes -EventWindow $win -ToleranceSeconds $tolDc
                $state = $cmp.State; $nk = $cmp.NoteKey; $na = $cmp.NoteArgs
            }
            [void]$out.Add((New-AuditFinding -Source 'Logon' -HostName $domainHost -Account $Target.Display -ObjectType 'ADAttribute' `
                -DetailKey 'Detail.AD.PwdLastSet' -DetailArgs @($(if ($pwdLastSet) { $pwdLastSet } else { '@Value.Never' }), $any.PwdLastSetVersion, $any.PwdLastSetOriginatingDsa) `
                -Timestamp $pwdLastSet -Method 'ADAttributes (Ldap)' -Context $Context -AccountSid $Target.Sid -AccountScope 'Domain' -AccountMatch 'Sid' `
                -CorrelationKey ($domainHost + '|AD|pwdLastSet') -CrossCheck $state -CrossCheckNoteKey $nk -CrossCheckNoteArgs $na `
                -Attributes @{ Attribute = 'pwdLastSet'; Value = $pwdLastSet; PerDc = $pwdValues; Version = $any.PwdLastSetVersion; OriginatingDsa = $any.PwdLastSetOriginatingDsa } `
                -Evidence $allEv))

            # lastLogonTimestamp (repliziert, bis ~14 Tage Verzug) vs. Maximum aller lastLogon
            $llt = ConvertFrom-AuditFileTime $any.lastLogonTimestamp
            $maxLl = $null; $maxDc = ''
            foreach ($dc in $adRecords.Keys) {
                $v = ConvertFrom-AuditFileTime $adRecords[$dc].lastLogon
                if ($v -and (-not $maxLl -or $v -gt $maxLl)) { $maxLl = $v; $maxDc = $dc }
            }
            $syncDays = 14
            if ($any.LogonTimeSyncIntervalDays) { $syncDays = [int]$any.LogonTimeSyncIntervalDays }
            if ($anyDcFailed) { $state = 'Unverifiable'; $nk = 'Note.AD.DcUnavailable'; $na = @() }
            elseif (-not $llt -and -not $maxLl) { $state = 'Confirmed'; $nk = 'Note.PointInTime.NeverNoEvents'; $na = @() }
            elseif ($llt -and (-not $maxLl -or $llt -gt $maxLl.AddSeconds($tolDc))) { $state = 'Conflict'; $nk = 'Note.AD.LltNewerThanLastLogon'; $na = @($llt, $maxLl) }
            elseif (-not $llt -or ($maxLl - $llt).TotalDays -gt ($syncDays + 1)) { $state = 'Conflict'; $nk = 'Note.AD.LltStale'; $na = @($syncDays) }
            else { $state = 'Confirmed'; $nk = 'Note.AD.LltConsistent'; $na = @($syncDays) }
            [void]$out.Add((New-AuditFinding -Source 'Logon' -HostName $domainHost -Account $Target.Display -ObjectType 'ADAttribute' `
                -DetailKey 'Detail.AD.LastLogonTimestamp' -DetailArgs @($(if ($llt) { $llt } else { '@Value.Never' }), $(if ($maxLl) { $maxLl } else { '@Value.Never' }), $maxDc) `
                -Timestamp $llt -Method 'ADAttributes (Ldap)' -Context $Context -AccountSid $Target.Sid -AccountScope 'Domain' -AccountMatch 'Sid' `
                -CorrelationKey ($domainHost + '|AD|lastLogonTimestamp') -CrossCheck $state -CrossCheckNoteKey $nk -CrossCheckNoteArgs $na `
                -Attributes @{ Attribute = 'lastLogonTimestamp'; Value = $llt; MaxLastLogon = $maxLl; MaxLastLogonDc = $maxDc; SyncIntervalDays = $syncDays } `
                -Evidence $allEv))

            # Kontozustand (autoritative Einzelquelle) - SPNs deuten auf Nutzung als Dienstkonto hin
            $uac = [int]$any.userAccountControl
            $spns = @($any.servicePrincipalName | Where-Object { $_ })
            $flags = @()
            if ($uac -band 0x2) { $flags += 'ACCOUNTDISABLE' }
            if ($uac -band 0x10000) { $flags += 'DONT_EXPIRE_PASSWORD' }
            if ($uac -band 0x100000) { $flags += 'NOT_DELEGATED' }
            if ($uac -band 0x400000) { $flags += 'DONT_REQ_PREAUTH' }
            [void]$out.Add((New-AuditFinding -Source 'Logon' -HostName $domainHost -Account $Target.Display -ObjectType 'ADAccount' `
                -DetailKey 'Detail.AD.Account' -DetailArgs @(($flags -join ', '), $spns.Count, $any.adminCount, (ConvertFrom-AuditTimeString $any.whenCreated)) `
                -Timestamp (ConvertFrom-AuditTimeString $any.whenChanged) -Method 'ADAttributes (Ldap)' -Context $Context -AccountSid $Target.Sid `
                -AccountScope 'Domain' -AccountMatch 'Sid' -CorrelationKey ($domainHost + '|AD|account') -CrossCheck 'NotChecked' -Authoritative `
                -CrossCheckNoteKey 'Note.AD.Authoritative' `
                -Attributes @{ UserAccountControl = $uac; Flags = $flags; ServicePrincipalNames = $spns; AdminCount = $any.adminCount
                               WhenCreated = (ConvertFrom-AuditTimeString $any.whenCreated); SupportedEncryptionTypes = $any.'msDS-SupportedEncryptionTypes' } `
                -Evidence $allEv))
        }

        $out.ToArray()
    }
}
