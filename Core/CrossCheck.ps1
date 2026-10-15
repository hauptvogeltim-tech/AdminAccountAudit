# Abgleich zweier unabhaengiger Quellen (Zwei-Quellen-Prinzip).
#
# Abweichungen werden als Zustand am Fund markiert, nie stillschweigend aufgeloest.
# Drei Grundmuster:
#   Compare-AuditTimeline    : Ereignis-Zeitreihen gegeneinander (z. B. 4624 Typ 10 vs. TS-Log 21)
#   Compare-AuditPointInTime : ein Attribut-Zeitpunkt gegen Ereignisse (z. B. lastLogon vs. 4768/4776)
#   Compare-AuditKeyedSet    : Konfigurationsobjekte per Schluessel (Tasks, Dienste - spaetere Kollektoren)

function Test-AuditInWindow {
    param([datetime]$Time, [object]$Window, [int]$ToleranceSeconds = 0)
    if ($null -eq $Window) { return $false }
    $start = Get-AuditProperty $Window 'Start'
    $end = Get-AuditProperty $Window 'End'
    $tol = [timespan]::FromSeconds($ToleranceSeconds)
    if ($null -ne $start -and $Time -lt ([datetime]$start - $tol)) { return $false }
    if ($null -ne $end -and $Time -gt ([datetime]$end + $tol)) { return $false }
    return $true
}

function Compare-AuditTimeline {
    <#
      Primary/Secondary: Objekte mit Eigenschaft .Time (UTC-DateTime).
      PrimaryWindow/SecondaryWindow: @{Start;End} oder $null, wenn die Quelle nicht verfuegbar war.
      NeedsMatch {param($p)}  : muss dieses Primaerereignis eine Entsprechung haben? (sonst NotChecked)
      CanMatch   {param($p,$s)}: duerfen p und s einander zugeordnet werden?
      Zuordnung: jedes Sekundaerereignis hoechstens einmal, naechstgelegenes zuerst.

      Rueckgabe:
        Primary   : je Primaerobjekt @{ Item; State; Match }
        Secondary : je Sekundaerobjekt @{ Item; State; Match }  (State Confirmed oder OnlySecondary/NotChecked/Unverifiable)
    #>
    param(
        [object[]]$Primary = @(),
        [object[]]$Secondary = @(),
        [object]$PrimaryWindow,
        [object]$SecondaryWindow,
        [int]$ToleranceSeconds = 120,
        [scriptblock]$NeedsMatch = { param($p) $true },
        [scriptblock]$CanMatch = { param($p, $s) $true }
    )
    $tol = [timespan]::FromSeconds($ToleranceSeconds)
    $secList = @($Secondary | Sort-Object { $_.Time })
    $used = New-Object 'bool[]' ($secList.Count)
    $secMatch = New-Object 'object[]' ($secList.Count)
    $primaryOut = New-Object System.Collections.ArrayList

    foreach ($p in @($Primary | Sort-Object { $_.Time })) {
        if (-not (& $NeedsMatch $p)) {
            # Darf trotzdem eine Entsprechung "verbrauchen", damit diese nicht als OnlySecondary erscheint
            $idx = Find-AuditNearest -Item $p -List $secList -Used $used -Tolerance $tol -CanMatch $CanMatch
            $m = $null
            if ($idx -ge 0) { $used[$idx] = $true; $secMatch[$idx] = $p; $m = $secList[$idx] }
            $state = if ($m) { 'Confirmed' } else { 'NotChecked' }
            [void]$primaryOut.Add(@{ Item = $p; State = $state; Match = $m })
            continue
        }
        if ($null -eq $SecondaryWindow) {
            [void]$primaryOut.Add(@{ Item = $p; State = 'Unverifiable'; Match = $null }); continue
        }
        $idx = Find-AuditNearest -Item $p -List $secList -Used $used -Tolerance $tol -CanMatch $CanMatch
        if ($idx -ge 0) {
            $used[$idx] = $true; $secMatch[$idx] = $p
            [void]$primaryOut.Add(@{ Item = $p; State = 'Confirmed'; Match = $secList[$idx] })
        }
        elseif (Test-AuditInWindow -Time $p.Time -Window $SecondaryWindow -ToleranceSeconds $ToleranceSeconds) {
            [void]$primaryOut.Add(@{ Item = $p; State = 'OnlyPrimary'; Match = $null })
        }
        else {
            [void]$primaryOut.Add(@{ Item = $p; State = 'NotChecked'; Match = $null })
        }
    }

    $secondaryOut = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $secList.Count; $i++) {
        $s = $secList[$i]
        if ($used[$i]) { [void]$secondaryOut.Add(@{ Item = $s; State = 'Confirmed'; Match = $secMatch[$i] }); continue }
        if ($null -eq $PrimaryWindow) { $state = 'Unverifiable' }
        elseif (Test-AuditInWindow -Time $s.Time -Window $PrimaryWindow -ToleranceSeconds $ToleranceSeconds) { $state = 'OnlySecondary' }
        else { $state = 'NotChecked' }
        [void]$secondaryOut.Add(@{ Item = $s; State = $state; Match = $null })
    }

    @{ Primary = $primaryOut.ToArray(); Secondary = $secondaryOut.ToArray() }
}

function Find-AuditNearest {
    param($Item, [object[]]$List, [bool[]]$Used, [timespan]$Tolerance, [scriptblock]$CanMatch)
    $best = -1
    $bestDiff = [double]::MaxValue
    for ($i = 0; $i -lt $List.Count; $i++) {
        if ($Used[$i]) { continue }
        $diff = [math]::Abs(($List[$i].Time - $Item.Time).TotalSeconds)
        if ($diff -gt $Tolerance.TotalSeconds) { continue }
        if ($diff -lt $bestDiff -and (& $CanMatch $Item $List[$i])) { $best = $i; $bestDiff = $diff }
    }
    $best
}

function Merge-AuditCrossCheckState {
    # Fasst die Zustaende der Einzelereignisse eines aggregierten Funds zusammen.
    param([string[]]$States)
    $u = @($States | Sort-Object -Unique)
    if ($u.Count -eq 0) { return 'NotChecked' }
    if ($u.Count -eq 1) { return $u[0] }
    if ($u -contains 'Conflict') { return 'Conflict' }
    $checkable = @($u | Where-Object { $_ -notin @('NotChecked', 'Unverifiable') })
    if ($checkable.Count -eq 0) { return 'Unverifiable' }
    if ($checkable.Count -eq 1 -and $checkable[0] -eq 'Confirmed') { return 'Confirmed' }
    if ($checkable.Count -eq 1) { return $checkable[0] }
    return 'Partial'
}

function Compare-AuditPointInTime {
    <#
      Vergleicht einen Attribut-Zeitpunkt (z. B. lastLogon eines DCs) mit Ereigniszeiten
      derselben Stelle. EventWindow = Zeitfenster des Logs (@{Start;End}) oder $null.
      Rueckgabe @{ State; NoteKey; NoteArgs; NewestEvent }.
    #>
    param(
        [object]$AttributeTime,
        [datetime[]]$EventTimes = @(),
        [object]$EventWindow,
        [int]$ToleranceSeconds = 300
    )
    if ($null -eq $EventWindow) {
        return @{ State = 'Unverifiable'; NoteKey = 'Note.PointInTime.NoEvents'; NoteArgs = @(); NewestEvent = $null }
    }
    $tol = [timespan]::FromSeconds($ToleranceSeconds)
    $newest = $null
    if ($EventTimes.Count -gt 0) { $newest = ($EventTimes | Measure-Object -Maximum).Maximum }

    if ($null -eq $AttributeTime) {
        if ($newest) {
            return @{ State = 'Conflict'; NoteKey = 'Note.PointInTime.NeverButEvents'; NoteArgs = @($newest); NewestEvent = $newest }
        }
        return @{ State = 'Confirmed'; NoteKey = 'Note.PointInTime.NeverNoEvents'; NoteArgs = @(); NewestEvent = $null }
    }
    $attr = [datetime]$AttributeTime
    if ($newest -and $newest -gt ($attr + $tol)) {
        return @{ State = 'Conflict'; NoteKey = 'Note.PointInTime.EventNewer'; NoteArgs = @($newest, $attr); NewestEvent = $newest }
    }
    if ($newest -and [math]::Abs(($newest - $attr).TotalSeconds) -le $tol.TotalSeconds) {
        return @{ State = 'Confirmed'; NoteKey = 'Note.PointInTime.Match'; NoteArgs = @($newest, $attr); NewestEvent = $newest }
    }
    $start = Get-AuditProperty $EventWindow 'Start'
    if ($null -ne $start -and $attr -lt ([datetime]$start - $tol)) {
        return @{ State = 'NotChecked'; NoteKey = 'Note.PointInTime.BeforeWindow'; NoteArgs = @($attr, $start); NewestEvent = $newest }
    }
    return @{ State = 'OnlySecondary'; NoteKey = 'Note.PointInTime.NoMatchingEvent'; NoteArgs = @($attr); NewestEvent = $newest }
}

function Compare-AuditKeyedSet {
    <#
      Abgleich von Konfigurationsobjekten zweier Methoden per Schluessel.
      Fields: Felder, die in beiden Quellen gleich sein muessen (sonst Conflict mit Feldliste).
      Rueckgabe: je Schluessel @{ Key; State; Primary; Secondary; Differences }
    #>
    param(
        [object[]]$Primary = @(),
        [object[]]$Secondary = @(),
        [Parameter(Mandatory)][scriptblock]$KeySelector,
        [string[]]$Fields = @(),
        [bool]$SecondaryAvailable = $true
    )
    $p = @{}; $s = @{}
    foreach ($i in $Primary) { $p[[string](& $KeySelector $i)] = $i }
    foreach ($i in $Secondary) { $s[[string](& $KeySelector $i)] = $i }
    $keys = @(@($p.Keys) + @($s.Keys) | Sort-Object -Unique)
    foreach ($k in $keys) {
        $a = $p[$k]; $b = $s[$k]
        $diff = @()
        if ($a -and $b) {
            foreach ($f in $Fields) {
                $va = [string](Get-AuditProperty $a $f); $vb = [string](Get-AuditProperty $b $f)
                if ($va -ne $vb) { $diff += ('{0}: "{1}" <> "{2}"' -f $f, $va, $vb) }
            }
            $state = if ($diff.Count -gt 0) { 'Conflict' } else { 'Confirmed' }
        }
        elseif ($a) { $state = if ($SecondaryAvailable) { 'OnlyPrimary' } else { 'Unverifiable' } }
        else { $state = 'OnlySecondary' }
        @{ Key = $k; State = $state; Primary = $a; Secondary = $b; Differences = $diff }
    }
}
