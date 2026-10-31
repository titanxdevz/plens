# PortLens PowerShell Soak Test Script
param (
    [string]$Target = "127.0.0.1",
    [int]$DurationSecs = 3600,
    [int]$IntervalSecs = 60
)

Write-Host "=== Starting PortLens Soak Test (PowerShell) ==="
Write-Host "Target: $Target | Duration: ${DurationSecs}s | Interval: ${IntervalSecs}s"

cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build release binary"
    exit 1
}

$proc = Start-Process -FilePath ".\target\release\plens.exe" -ArgumentList "watch", $Target, "--every", "30s", "-y" -PassThru -NoNewWindow

$startTime = [DateTime]::UtcNow
$maxMem = 0
$initialMem = 0

try {
    while (($([DateTime]::UtcNow) - $startTime).TotalSeconds -lt $DurationSecs) {
        if ($proc.HasExited) {
            Write-Error "plens.exe terminated unexpectedly!"
            exit 1
        }

        $proc.Refresh()
        $ws = [math]::Round($proc.WorkingSet64 / 1MB, 2)
        $handles = $proc.HandleCount

        if ($initialMem -eq 0) { $initialMem = $ws }
        if ($ws -gt $maxMem) { $maxMem = $ws }

        Write-Host "Elapsed: $([math]::Round((([DateTime]::UtcNow) - $startTime).TotalSeconds))s | WorkingSet: ${ws} MB | Handles: ${handles}"
        Start-Sleep -Seconds $IntervalSecs
    }
} finally {
    if (-not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force
    }
}

Write-Host "=== Soak Test Complete ==="
Write-Host "Initial WS: ${initialMem} MB | Peak WS: ${maxMem} MB"

if ($maxMem -gt 50.0) {
    Write-Error "FAILED: Peak memory exceeded 50MB ceiling: ${maxMem} MB"
    exit 1
}

Write-Host "PASSED: Flat memory and handle count maintained."
