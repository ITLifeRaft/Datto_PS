<#
.SYNOPSIS
  System Health Observer (Phase-1 / Read-Only) – Datto-ready (superset build)

.DESCRIPTION
  - Scans recent Windows Event Logs, classifies (Noise / Known_Safe / Known_Unsafe / Unknown).
  - Writes local artifacts to C:\Tools\Datto_logs: timestamped JSON + TXT, plus Unknowns append file.
  - Updates Datto RMM UDF via HKLM:\SOFTWARE\CentraStage\CustomN (Status or Summary, your choice).
  - Emits compact JSON result and exit codes via your Datto wrapper at the end.
  Phase-1: NO remediation actions.

.VERSION
  1.0.8 (2026-02-19)
  - Restores: Levels/MaxEventsPerLog, artifacts, cleanup, SCM 7031 SafeKnown logic, wrapper-only markers.
  - Adds: Custom Noise Tuning block (provider+ID / provider-only / message regex / time-boxed),
          Unknowns appended to EventLog_Observer_.txt, UdfMode = Status or Summary.
#>

[CmdletBinding()]
param(
    # Lookback window & targeting
    [int]$LookbackHours = 168,  # 7 days
    [string[]]$LogNames = @('System','Application','Security'),
    [ValidateSet('Critical','Error','Warning','Information','Verbose')]
    [string[]]$Levels   = @('Critical','Error'),
    [int]$MaxEventsPerLog = 1000,

    # Local artifact path
    [string]$OutputFolder = "C:\Tools\Datto_logs",

    # Auto-cleanup controls
    [int]$RetentionDays = 14,
    [switch]$DisableCleanup,

    # UDF settings (Datto Agent reads HKLM:\SOFTWARE\CentraStage\Custom1..30)
    [int]$UdfNumber = 23,
    [string]$UdfLabel = "WINDOWS LOGS STATUS",
    [ValidateSet('Status','Summary')]
    [string]$UdfMode = 'Summary',   # <- 'Summary' per your latest request. Use 'Status' to revert original behavior.
    [switch]$DisableUdfUpdate,

    # Optional: start each run by truncating the Unknowns append file
    [switch]$TruncateObserverFile,

    # Verbosity
    [switch]$Quiet
)

# -------------------------------
# 0) Global Settings & Constants
# -------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RemediationEnabled    = $false     # Phase-1 is read-only

# Ensure output path exists
if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null }

$UtcStamp        = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$ComputerName    = $env:COMPUTERNAME
$ObserverVersion = '1.3.0'

$LevelMap = @{
    'Critical'    = 1
    'Error'       = 2
    'Warning'     = 3
    'Information' = 4
    'Verbose'     = 5
}

# -------------------------------
# 1) POLICY (Baseline)
# -------------------------------

# Baseline noise to suppress (you can extend in the Tuning section)
$NoiseRules = @(
    @{ Provider='Service Control Manager'; EventId=7036; MessagePattern='entered the running state' },
    @{ Provider='Service Control Manager'; EventId=7036; MessagePattern='entered the stopped state'  }
)

# Known SAFE patterns (recommendations only in Phase-1)
$SafeKnownRules = @(
    # SCM 7031 – repeated service crash within 10 minutes  (>=3 times in 10 minutes)
    @{
        Provider='Service Control Manager'
        EventId=7031
        Condition = {
            param($EventsForKey)

            # Use only events that truly carry a service name in Properties[0].Value
            $withSvc = $EventsForKey | Where-Object {
                $_ -and
                ($_.PSObject.Properties.Name -contains 'Properties') -and
                $_.Properties -and
                (($_.Properties | Measure-Object).Count -gt 0) -and
                $_.Properties[0] -and
                ($_.Properties[0].PSObject.Properties.Name -contains 'Value') -and
                $_.Properties[0].Value
            }
            if (-not $withSvc) { return $false }

            $byService = $withSvc | Group-Object { $_.Properties[0].Value }
            $window  = [TimeSpan]::FromMinutes(10)

            foreach ($g in $byService) {
                $ordered = $g.Group | Sort-Object TimeCreated
                for ($i = 0; $i -lt $ordered.Count; $i++) {
                    $start = $ordered[$i].TimeCreated
                    $count = ($ordered | Where-Object {
                        $_.TimeCreated -ge $start -and $_.TimeCreated -le ($start + $window)
                    }).Count
                    if ($count -ge 3) { return $true }
                }
            }
            return $false
        }
        Recommendation = {
            param($EventsForKey)
            "Service crash pattern detected (≥3 times in 10 minutes). Phase-2: restart the service, collect crash logs, check recent updates/add-ons, verify dependencies."
        }
    },

    # SCM 7031 – single crash with automatic restart (treat as SafeKnown)
    @{
        Provider='Service Control Manager'
        EventId=7031
        Condition = {
            param($EventsForKey)
            $EventsForKey | Where-Object {
                $_.Message -match 'corrective action.*Restart the service'
            } | Select-Object -First 1 | ForEach-Object { return $true }
            return $false
        }
        Recommendation = {
            param($EventsForKey)
            "Service terminated once and was auto-restarted. Phase-2: collect logs/crash info; if recurring, apply repeated-crash playbook."
        }
    }
)

# Known UNSAFE patterns (always escalate, never auto-fix)
$UnsafeKnownRules = @(
    @{ Provider='Microsoft-Windows-BitLocker-Driver'; EventId=24620; Escalation='BitLocker/volume protection issue. Gather logs; escalate to Tier-2.' },
    @{ Provider='Ntfs'; EventId=55; Escalation='File system issue. Schedule chkdsk during maintenance; verify backups; escalate.' },
    @{ Provider='Disk'; EventId=7;  Escalation='Disk read error (possible hardware/storage). Escalate immediately.' }
)

# ============================ >>> CUSTOM NOISE TUNING <<< ============================
# Add *additional* filters here. These augment (do not replace) the defaults above.
# ────────────────────────────────────────────────────────────────────────────────────
# 1) Provider + EventID (explicit)
#    EXAMPLE: Add-NoiseProviderId 'DNS Client Events' 1014
# 2) Provider only (all events from this source become Noise)
#    EXAMPLE: Add-NoiseProviderOnly 'Contoso-Agent'
# 3) Message regex (case-insensitive) – if message matches, treat as Noise
#    EXAMPLE: Add-NoiseMessagePattern '.*transient network error.*'
# 4) Time-boxed suppression until a date (UTC)
#    EXAMPLE: Add-NoiseUntil 'NETLOGON' 5719 '2026-03-15T00:00:00Z'

# Helpers to register noise rules dynamically
$Script:NoiseProviderOnly   = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
$Script:NoiseMessageRegexes = New-Object System.Collections.Generic.List[regex]
$Script:NoiseUntil          = New-Object System.Collections.Generic.List[pscustomobject] # Provider, Id, UntilUtc

function Add-NoiseProviderId([string]$Provider, [int[]]$Ids) {
    if (-not $NoiseRules) { $NoiseRules = @() }
    foreach ($i in $Ids) { $NoiseRules += @{ Provider=$Provider; EventId=$i } }
}
function Add-NoiseProviderOnly([string]$Provider) {
    [void]$Script:NoiseProviderOnly.Add($Provider)
}
function Add-NoiseMessagePattern([string]$Pattern) {
    $Script:NoiseMessageRegexes.Add([regex]::new($Pattern,'IgnoreCase'))
}
function Add-NoiseUntil([string]$Provider, [int]$Id, [string]$UntilUtc) {
    $utc = [datetime]::Parse($UntilUtc).ToUniversalTime()
    $Script:NoiseUntil.Add([pscustomobject]@{ Provider=$Provider; Id=$Id; Until=$utc })
}

# ---- Add your custom tuning lines below this line ----
# Add-NoiseProviderId 'DNS Client Events' 1014
# Add-NoiseProviderOnly 'MyThirdPartyAgent'
# Add-NoiseMessagePattern '.*connection reset by peer.*'
# Add-NoiseUntil 'NETLOGON' 5719 '2026-03-15T00:00:00Z'
# ---- Add your custom tuning lines above this line ----
# ========================== <<< END CUSTOM NOISE TUNING >>> ==========================

# -------------------------------
# 2) Helpers (incl. Cleanup & UDF)
# -------------------------------
function Get-LevelFilter {
    param([string[]]$Levels)
    $Levels | ForEach-Object { $LevelMap[$_] }
}

function Read-RecentEvents {
    param(
        [string]$LogName,
        [int]$Hours,
        [int]$Max = 1000,
        [int[]]$LevelInts
    )
    $start = (Get-Date).AddHours(-1 * $Hours)
    $filter = @{ LogName=$LogName; StartTime=$start }
    if ($LevelInts -and $LevelInts.Count -gt 0) { $filter['Level'] = $LevelInts }

    try {
        Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop
    } catch {
        Write-Verbose ("Failed reading log {0}: {1}" -f $LogName, $_.Exception.Message)
        @()
    }
}

function Normalize-Event {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$e)
    $msg = $null
    try { $msg = $e.FormatDescription() } catch { $msg = $null }
    [pscustomobject]@{
        Provider     = $e.ProviderName
        EventId      = $e.Id
        Level        = $e.LevelDisplayName
        TimeCreated  = $e.TimeCreated.ToUniversalTime()
        MachineName  = $e.MachineName
        Message      = $msg
        Properties   = $e.Properties
    }
}

function Matches-Noise {
    param($Event)
    # Time-boxed per-provider+id
    foreach ($rule in $Script:NoiseUntil) {
        if ($Event.Provider -eq $rule.Provider -and $Event.EventId -eq $rule.Id -and (Get-Date).ToUniversalTime() -lt $rule.Until) {
            return $true
        }
    }
    # Provider-only
    if ($Script:NoiseProviderOnly.Contains($Event.Provider)) { return $true }

    # Explicit provider+id rules
    foreach ($rule in $NoiseRules) {
        if ($Event.Provider -eq $rule.Provider -and $Event.EventId -eq $rule.EventId) {
            if ($rule.ContainsKey('MessagePattern')) {
                if ($Event.Message -and ($Event.Message -match $rule.MessagePattern)) { return $true }
            } else { return $true }
        }
    }

    # Message regex rules
    foreach ($rx in $Script:NoiseMessageRegexes) {
        if ($Event.Message -and $rx.IsMatch($Event.Message)) { return $true }
    }

    return $false
}

function Evaluate-SafeKnown {  # returns recommendation string or $null
    param($Events)
    foreach ($rule in $SafeKnownRules) {
        if ($Events[0].Provider -eq $rule.Provider -and $Events[0].EventId -eq $rule.EventId) {
            try {
                if ($rule.Condition.Invoke($Events)) {
                    return $rule.Recommendation.Invoke($Events)
                }
            } catch {
                Write-Verbose ("SafeKnown rule error for {0}/{1}: {2}" -f $Events[0].Provider, $Events[0].EventId, $_.Exception.Message)
            }
        }
    }
    return $null
}

function Evaluate-UnsafeKnown { # returns escalation string or $null
    param($Events)
    foreach ($rule in $UnsafeKnownRules) {
        if ($Events[0].Provider -eq $rule.Provider -and $Events[0].EventId -eq $rule.EventId) {
            return $rule.Escalation
        }
    }
    return $null
}

function Remove-OldArtifacts {
    param([string]$Folder, [int]$Days)
    try {
        if (-not (Test-Path $Folder)) { return }
        $cutoff = (Get-Date).AddDays(-1 * $Days)
        $patterns = @("EventLog_Observer_*.json","EventLog_Observer_*.txt")
        $deleted = 0
        foreach ($pat in $patterns) {
            Get-ChildItem -Path $Folder -Filter $pat -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoff } |
                ForEach-Object {
                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                    $deleted++
                }
        }
        if (-not $Quiet) { Write-Output ("Cleanup: removed {0} file(s) older than {1} day(s) from {2}" -f $deleted, $Days, $Folder) }
    } catch {
        Write-Verbose ("Cleanup error: {0}" -f $_.Exception.Message)
    }
}

function Set-DeviceUdf {
    param(
        [Parameter(Mandatory)][int]$UdfNumber,
        [Parameter(Mandatory)][string]$Value
    )
    # UDF value must be <=255 chars.
    $safe = if ($Value.Length -gt 255) { $Value.Substring(0,255) } else { $Value }
    $regKey = 'HKLM:\SOFTWARE\CentraStage'
    $valueName = 'Custom{0}' -f $UdfNumber

    try {
        if (-not (Test-Path $regKey)) { New-Item -Path 'HKLM:\SOFTWARE' -Name 'CentraStage' -Force | Out-Null }
        New-ItemProperty -Path $regKey -Name $valueName -PropertyType String -Value $safe -Force | Out-Null
        if (-not $Quiet) { Write-Output ("UDF {0} updated to: {1}" -f $UdfNumber, $safe) }
    } catch {
        Write-Verbose ("Failed to set UDF {0}: {1}" -f $UdfNumber, $_.Exception.Message)
    }
}

# -------------------------------
# 3) MAIN – Collect → Classify → Summarize
# -------------------------------
# Auto-cleanup before writing new artifacts
if (-not $DisableCleanup) { Remove-OldArtifacts -Folder $OutputFolder -Days $RetentionDays }

# Unknowns append file (always same name)
$observerAppendPath = Join-Path $OutputFolder 'EventLog_Observer_.txt'
if ($TruncateObserverFile -and (Test-Path $observerAppendPath)) {
    Clear-Content -Path $observerAppendPath -ErrorAction SilentlyContinue
}

$levelInts  = Get-LevelFilter -Levels $Levels
$rawEvents  = New-Object System.Collections.Generic.List[object]

foreach ($log in $LogNames) {
    $raw = Read-RecentEvents -LogName $log -Hours $LookbackHours -Max $MaxEventsPerLog -LevelInts $levelInts
    foreach ($e in $raw) { $rawEvents.Add((Normalize-Event $e)) }
}

$groups = $rawEvents | Group-Object { '{0}|{1}' -f $_.Provider, $_.EventId }

$buckets = @{
    Noise               = @()
    Known_Issue_Safe    = @()
    Known_Issue_Unsafe  = @()
    Unknown             = @()
}

$unknownTextLines = New-Object System.Collections.Generic.List[string]

foreach ($g in $groups) {
    $eventsForKey   = $g.Group
    $representative = $eventsForKey | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $keyParts       = $g.Name.Split('|')
    $provider       = $keyParts[0]
    $eventId        = [int]$keyParts[1]
    $count          = $eventsForKey.Count

    # Noise?
    $isNoise = $false
    foreach ($ev in $eventsForKey) {
        if (Matches-Noise $ev) { $isNoise = $true; break }
    }
    if ($isNoise) {
        $buckets.Noise += [pscustomobject]@{
            Provider    = $provider
            EventId     = $eventId
            Count       = $count
            LastSeenUtc = $representative.TimeCreated
        }
        continue
    }

    # Safe-known?
    $recommendation = Evaluate-SafeKnown $eventsForKey
    if ($null -ne $recommendation) {
        $buckets.Known_Issue_Safe += [pscustomobject]@{
            Provider       = $provider
            EventId        = $eventId
            Count          = $count
            LastSeenUtc    = $representative.TimeCreated
            Recommendation = $recommendation
        }
        continue
    }

    # Unsafe-known?
    $escalation = Evaluate-UnsafeKnown $eventsForKey
    if ($null -ne $escalation) {
        $buckets.Known_Issue_Unsafe += [pscustomobject]@{
            Provider    = $provider
            EventId     = $eventId
            Count       = $count
            LastSeenUtc = $representative.TimeCreated
            Escalation  = $escalation
        }
        continue
    }

    # Unknown
    $sample = $representative.Message
    if ($sample -and $sample.Length -gt 500) { $sample = $sample.Substring(0,500) + '...' }
    $buckets.Unknown += [pscustomobject]@{
        Provider      = $provider
        EventId       = $eventId
        Count         = $count
        LastSeenUtc   = $representative.TimeCreated
        SampleMessage = $sample
    }
    # Append one-line row for Unknowns file
    $unknownTextLines.Add( ('{0} | {1} | ID={2} | Count={3} | {4}' -f `
        ($representative.TimeCreated.ToString('s')), $provider, $eventId, $count, ($sample -replace '\r?\n',' ')) )
}

$summary = [ordered]@{
    ObserverVersion = $ObserverVersion
    ComputerName    = $ComputerName
    UtcStamp        = $UtcStamp
    LookbackHours   = $LookbackHours
    LogsReviewed    = $LogNames
    LevelsReviewed  = $Levels
    TotalEvents     = $rawEvents.Count
    Buckets         = [ordered]@{
        Noise              = $buckets.Noise
        Known_Issue_Safe   = $buckets.Known_Issue_Safe
        Known_Issue_Unsafe = $buckets.Known_Issue_Unsafe
        Unknown            = $buckets.Unknown
    }
}

# -------------------------------
# 4) Derive WINDOWS LOGS STATUS + UDF value
# -------------------------------
$knownUnsafe = @($summary.Buckets.Known_Issue_Unsafe).Count
$knownSafe   = @($summary.Buckets.Known_Issue_Safe).Count
$unknown     = @($summary.Buckets.Unknown).Count

$windowsLogsStatus = if ($knownUnsafe -gt 0) { 'Attention' }
                     elseif ( ($unknown -gt 0) -or ($knownSafe -gt 0) ) { 'Review' }
                     else { 'Healthy' }

# UDF value: Status (original) or Summary (new)
$udfSummaryLine = "Scanned {0} events. Noise={1}, Safe={2}, Unsafe={3}, Unknown={4}. STATUS={5}" -f `
                  $summary.TotalEvents, @($summary.Buckets.Noise).Count, $knownSafe, $knownUnsafe, $unknown, $windowsLogsStatus
$udfValue = if ($UdfMode -eq 'Status') { $windowsLogsStatus } else { $udfSummaryLine }

if (-not $DisableUdfUpdate) {
    Set-DeviceUdf -UdfNumber $UdfNumber -Value $udfValue
}

# -------------------------------
# 5) Local artifacts
# -------------------------------
# Timestamped JSON & TXT (as in your original)
$outJson = Join-Path $OutputFolder ("EventLog_Observer_{0}_{1}.json" -f $ComputerName,$UtcStamp)
$summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $outJson -Encoding UTF8

$humanLine = ("Health check: scanned {0} events. Noise={1}, Safe={2}, Unsafe={3}, Unknown={4}. STATUS={5}" -f `
    $summary.TotalEvents, @($summary.Buckets.Noise).Count, $knownSafe, $knownUnsafe, $unknown, $windowsLogsStatus)

$outTxt = Join-Path $OutputFolder ("EventLog_Observer_{0}_{1}.txt" -f $ComputerName,$UtcStamp)
@(
  "System Health Observer (Phase-1, Read-Only)",
  "Computer     : $($summary.ComputerName)",
  "TimestampUtc : $($summary.UtcStamp)",
  "LookbackHours: $($summary.LookbackHours)",
  "TotalEvents  : $($summary.TotalEvents)",
  "Noise        : $(@($summary.Buckets.Noise).Count)",
  "KnownSafe    : $knownSafe",
  "KnownUnsafe  : $knownUnsafe",
  "Unknown      : $unknown",
  "WINDOWS LOGS STATUS (UDF $UdfNumber / $UdfMode): $udfValue",
  "",
  $humanLine
) | Out-File -FilePath $outTxt -Encoding UTF8

# Unknowns append file (stable name) — as requested
if ($unknownTextLines.Count -gt 0) {
    "===== Unknown Events appended @ {0} =====" -f (Get-Date).ToString('s') | Out-File -FilePath $observerAppendPath -Encoding UTF8 -Append
    $unknownTextLines | Out-File -FilePath $observerAppendPath -Encoding UTF8 -Append
    "" | Out-File -FilePath $observerAppendPath -Encoding UTF8 -Append
}

if (-not $Quiet) {
    Write-Output ("JSON written: {0}" -f $outJson)
    Write-Output ("TXT  written: {0}" -f $outTxt)
    if ($unknownTextLines.Count -gt 0) { Write-Output ("Unknowns appended: {0}" -f $observerAppendPath) }
}

# ====================================================================================
# ================================ DATTO WRAPPER ====================================
# Your wrapper runs LAST. It emits the ONLY Datto result markers and exit codes.
# ====================================================================================

# === DATTO WRAPPER START ===
# Guard: if $summary wasn't created, build a minimal one to avoid nulls
if (-not $summary) {
    $summary = [ordered]@{
        ObserverVersion = "1.0.0"
        ComputerName    = $env:COMPUTERNAME
        UtcStamp        = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
        LookbackHours   = 24
        LogsReviewed    = @('System','Application')
        LevelsReviewed  = @('Critical','Error')
        TotalEvents     = 0
        Buckets         = [ordered]@{
            Noise              = @()
            Known_Issue_Safe   = @()
            Known_Issue_Unsafe = @()
            Unknown            = @()
        }
    }
}

# Compute quick counts
$noiseCount   = @($summary.Buckets.Noise).Count
$safeCount    = @($summary.Buckets.Known_Issue_Safe).Count
$unsafeCount  = @($summary.Buckets.Known_Issue_Unsafe).Count
$unknownCount = @($summary.Buckets.Unknown).Count

# Build a compact result object specifically for Datto's result pane
$result = [ordered]@{
    Computer       = $summary.ComputerName
    TimestampUtc   = $summary.UtcStamp
    LookbackHours  = $summary.LookbackHours
    TotalEvents    = $summary.TotalEvents
    Noise          = $noiseCount
    KnownSafe      = $safeCount
    KnownUnsafe    = $unsafeCount
    Unknown        = $unknownCount
    Examples = [ordered]@{
        KnownSafeExample   = if ($safeCount   -gt 0) { $summary.Buckets.Known_Issue_Safe  | Select-Object -First 1 } else { $null }
        KnownUnsafeExample = if ($unsafeCount -gt 0) { $summary.Buckets.Known_Issue_Unsafe| Select-Object -First 1 } else { $null }
        UnknownExample     = if ($unknownCount-gt 0) { $summary.Buckets.Unknown           | Select-Object -First 1 } else { $null }
    }
}

# Surface WINDOWS LOGS STATUS if computed
if ($windowsLogsStatus) { $result['WindowsLogsStatus'] = $windowsLogsStatus }

# Human-friendly one-liner for the component "Output" view
$humanLine = ("Health check: {0} events scanned. Noise={1}, Safe={2}, Unsafe={3}, Unknown={4}{5}" -f `
    $summary.TotalEvents, $noiseCount, $safeCount, $unsafeCount, $unknownCount,
    ($(if ($windowsLogsStatus) { "; STATUS=" + $windowsLogsStatus } else { "" }))
)

# === REQUIRED MARKERS FOR DATTO (literal) ===
Write-Output "<-Start Result->"
Write-Output ($result | ConvertTo-Json -Depth 6)
Write-Output "<-End Result->"

# Also print a brief human line
Write-Output $humanLine

# --- Exit code policy (wrapper owns final exit) ---
# 0 = Healthy or minor issues
# 1 = Attention needed (KnownUnsafe)
# 2 = Review (Unknown or KnownSafe present)
if ( $unsafeCount -gt 0 ) {
    exit 1   # Fail: ATTENTION
}
elseif ( $unknownCount -gt 0 -or $safeCount -gt 0 ) {
    exit 2   # Non-zero but many teams treat 2 as 'Warning'
}
else {
    exit 0   # Healthy
}
# === DATTO WRAPPER END ===

