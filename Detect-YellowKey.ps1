#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detects IoCs associated with the YellowKey TxF-based WinRE/BitLocker bypass.

.DESCRIPTION
    Scans all mounted volumes, the registry, event logs, and NTFS metadata for
    artifacts left by the YellowKey exploit. Checks include:
      - FsTx artifact directory and files (by path, size, and content)
      - CLFS magic bytes and checksum on .blf files
      - UTF-16 winpeshl.ini string embedded in CLFS log containers
      - KTM registry entries for known transaction GUIDs
      - $TXF_DATA alternate data stream on winpeshl.ini
      - TxF metadata directories on all volumes
      - KTM operational event log

.NOTES
    Must be run as Administrator to access System Volume Information and NTFS metadata.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Hits    = 0

# ---------------------------------------------------------------------------
# IoC Definitions
# ---------------------------------------------------------------------------

$TxnGuid       = "95F62703B343F111A92A005056975458"   # directory name (no dashes)
$TempFileGuid  = "98F62703B343F111A92A005056975458"   # zero-byte temp marker

$KTMGuids = @(
    "352AAA60-43A1-11F1-A92A-005056975458",
    "352AAA62-43A1-11F1-A92A-005056975458",
    "352AAA63-43A1-11F1-A92A-005056975458"
)

# First 16 bytes of both .blf files: CLFS signature + version + fixed checksum
$CLFSMagic = [byte[]](
    0x15, 0x00, 0x01, 0x00,   # CLFS signature
    0x02, 0x00, 0x02, 0x00,   # version 2.2
    0x00, 0x00, 0x00, 0x00,   # padding
    0x4B, 0x82, 0x4C, 0xC6    # CRC32 checksum (fixed for this artifact)
)

# UTF-16 LE encoded target path embedded in FsTxLogContainer*
$WinpeshlUTF16 = [System.Text.Encoding]::Unicode.GetBytes(
    "\??\X:\Windows\System32\winpeshl.ini"
)

# Expected files under FsTxLogs\ with their exact sizes
$FsTxFiles = [ordered]@{
    "FsTxLog.blf"                            = 65536
    "FsTxKtmLog.blf"                         = 65536
    "FsTxLogContainer00000000000000000001"    = 10485760
    "FsTxLogContainer00000000000000000002"    = 10485760
    "FsTxKtmLogContainer00000000000000000001" = 524288
    "FsTxKtmLogContainer00000000000000000002" = 524288
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Hit {
    param(
        [string]$Category,
        [string]$Detail,
        [string]$Path = ""
    )
    $script:Hits++
    $script:Results.Add([PSCustomObject]@{
        Category = $Category
        Detail   = $Detail
        Path     = $Path
    })
    Write-Host "[HIT] $Category" -ForegroundColor Red -NoNewline
    Write-Host " — $Detail" -ForegroundColor White
    if ($Path) {
        Write-Host "      $Path" -ForegroundColor Yellow
    }
}

function Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

# Returns $true if $Pattern bytes appear at $Offset in the file
function Test-BytesAt {
    param([string]$FilePath, [byte[]]$Pattern, [int]$Offset = 0)
    try {
        $fs  = [System.IO.File]::OpenRead($FilePath)
        $buf = New-Object byte[] $Pattern.Length
        [void]$fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        $read = $fs.Read($buf, 0, $Pattern.Length)
        $fs.Close()
        if ($read -ne $Pattern.Length) { return $false }
        for ($i = 0; $i -lt $Pattern.Length; $i++) {
            if ($buf[$i] -ne $Pattern[$i]) { return $false }
        }
        return $true
    }
    catch { return $false }
}

# Returns $true if $Pattern appears anywhere in the file
function Search-Bytes {
    param([string]$FilePath, [byte[]]$Pattern)
    try {
        $data = [System.IO.File]::ReadAllBytes($FilePath)
        $plen = $Pattern.Length
        $limit = $data.Length - $plen
        for ($i = 0; $i -le $limit; $i++) {
            $match = $true
            for ($j = 0; $j -lt $plen; $j++) {
                if ($data[$i + $j] -ne $Pattern[$j]) { $match = $false; break }
            }
            if ($match) { return $true }
        }
        return $false
    }
    catch { return $false }
}

# Format a raw 32-char GUID string as {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
function Format-Guid {
    param([string]$Raw)
    "{$($Raw.Insert(8,'-').Insert(13,'-').Insert(18,'-').Insert(23,'-'))}"
}

# ---------------------------------------------------------------------------
# Check 1 — FsTx artifact directory on all volumes
# ---------------------------------------------------------------------------
Write-Info "Scanning all volumes for FsTx artifact directory..."

$drives = Get-PSDrive -PSProvider FileSystem |
          Where-Object { $_.Root -match '^[A-Z]:\\$' }

foreach ($drive in $drives) {
    $sviPath  = Join-Path $drive.Root "System Volume Information\FsTx"
    $fstxBase = Join-Path $sviPath $TxnGuid

    # Broad check: any FsTx directory at all (catches variants with different GUIDs)
    if (Test-Path $sviPath) {
        $children = Get-ChildItem $sviPath -Directory
        foreach ($child in $children) {
            if ($child.Name -ne $TxnGuid) {
                Write-Hit "FsTx Dir (unknown GUID)" `
                    "Unexpected transaction GUID: $($child.Name)" `
                    $child.FullName
            }
        }
    }

    if (-not (Test-Path $fstxBase)) { continue }

    Write-Hit "FsTx Dir" "Known transaction GUID directory present" $fstxBase

    # --- Per-file checks ---
    $logsDir = Join-Path $fstxBase "FsTxLogs"

    foreach ($kv in $FsTxFiles.GetEnumerator()) {
        $fp = Join-Path $logsDir $kv.Key
        if (-not (Test-Path $fp)) { continue }

        $actualSize = (Get-Item $fp).Length
        $sizeOk     = ($actualSize -eq $kv.Value)

        Write-Hit "FsTx File" "$($kv.Key) — size $actualSize (expected $($kv.Value), match: $sizeOk)" $fp

        # CLFS magic + checksum on .blf files
        if ($kv.Key -like "*.blf") {
            if (Test-BytesAt -FilePath $fp -Pattern $CLFSMagic -Offset 0) {
                Write-Hit "CLFS Signature" "Magic bytes + CRC 0x4B824CC6 confirmed" $fp
            }
        }

        # winpeshl.ini UTF-16 LE string in log containers
        if ($kv.Key -like "FsTxLogContainer*") {
            if (Search-Bytes -FilePath $fp -Pattern $WinpeshlUTF16) {
                Write-Hit "Embedded Path" "winpeshl.ini target path (UTF-16) found in CLFS container" $fp
            }
        }
    }

    # Zero-byte temp marker
    $tempFile = Join-Path $fstxBase "FsTxTemp\$TempFileGuid"
    if (Test-Path $tempFile) {
        Write-Hit "FsTx Temp" "Zero-byte transaction temp marker present" $tempFile
    }
}

# ---------------------------------------------------------------------------
# Check 2 — KTM registry
# ---------------------------------------------------------------------------
Write-Info "Checking KTM registry for YellowKey transaction GUIDs..."

$ktmRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Ktm\ResourceManagers"
if (Test-Path $ktmRegPath) {
    $allGuids = $KTMGuids + @( (Format-Guid $TxnGuid).Trim('{}') )
    foreach ($guid in $allGuids) {
        $formatted = "{$guid}"
        $key = Get-ChildItem $ktmRegPath |
               Where-Object { $_.PSChildName -ieq $formatted }
        if ($key) {
            Write-Hit "KTM Registry" "YellowKey GUID registered: $formatted" `
                "$ktmRegPath\$formatted"
        }
    }
}

# ---------------------------------------------------------------------------
# Check 3 — $TXF_DATA alternate data stream on winpeshl.ini
# ---------------------------------------------------------------------------
Write-Info "Checking winpeshl.ini for `$TXF_DATA alternate data stream..."

$winpeshlLocations = @(
    "X:\Windows\System32\winpeshl.ini",
    "C:\Windows\System32\winpeshl.ini"
)
# Add winpeshl.ini on every mounted drive
foreach ($drive in $drives) {
    $winpeshlLocations += Join-Path $drive.Root "Windows\System32\winpeshl.ini"
}
$winpeshlLocations = $winpeshlLocations | Select-Object -Unique

foreach ($path in $winpeshlLocations) {
    if (-not (Test-Path $path)) { continue }
    $streams = Get-Item $path -Stream * 2>$null
    if ($streams | Where-Object { $_.Stream -eq '$TXF_DATA' }) {
        Write-Hit '$TXF_DATA ADS' "Pending transaction marker on winpeshl.ini" $path
    }
}

# ---------------------------------------------------------------------------
# Check 4 — TxF metadata directories on all volumes
# ---------------------------------------------------------------------------
Write-Info "Checking for active TxF metadata directories..."

foreach ($drive in $drives) {
    $txfLog = Join-Path $drive.Root '$Extend\$RmMetadata\$TxfLog'
    if (Test-Path $txfLog) {
        $items = Get-ChildItem $txfLog 2>$null
        if ($items) {
            Write-Hit "TxF Metadata" `
                "Active TxF log present on $($drive.Root) ($($items.Count) item(s))" `
                $txfLog
        }
    }
}

# ---------------------------------------------------------------------------
# Check 5 — KTM operational event log
# ---------------------------------------------------------------------------
Write-Info "Scanning KTM operational event log for YellowKey GUIDs..."

$allSearchGuids = ($KTMGuids + @($TxnGuid, $TempFileGuid)) -join "|"

try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-KtmRm/Operational" `
                           -MaxEvents 1000 `
                           -ErrorAction Stop
    foreach ($event in $events) {
        if ($event.Message -match $allSearchGuids) {
            $matched = [regex]::Match($event.Message, $allSearchGuids).Value
            Write-Hit "Event Log (KTM)" `
                "EventID $($event.Id) at $($event.TimeCreated) references GUID: $matched" `
                "Microsoft-Windows-KtmRm/Operational"
        }
    }
}
catch [System.Exception] {
    Write-Info "KTM Operational log unavailable or empty (normal on non-affected systems)"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host ("=" * 50) -ForegroundColor White
Write-Host "  YellowKey Detection Summary" -ForegroundColor White
Write-Host ("=" * 50) -ForegroundColor White

if ($script:Hits -eq 0) {
    Write-Host "[CLEAN] No YellowKey IoCs detected." -ForegroundColor Green
}
else {
    Write-Host "[ALERT] $($script:Hits) indicator(s) detected." -ForegroundColor Red
    Write-Host ""
    $script:Results | Format-Table Category, Detail, Path -AutoSize -Wrap
}
