# SentinelPy IDS / IPS - Disable Autostart Script
# Removes the SentinelPy_IDS task from Windows Task Scheduler.

$TaskName = "SentinelPy_IDS"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[*] Requesting Administrator privileges to remove scheduled task..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  SENTINELPY IDS / IPS - DISABLE AUTOSTART" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

try {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[+] Successfully stopped and removed scheduled task: $TaskName" -ForegroundColor Green
        Write-Host "[+] SentinelPy will no longer start automatically on boot." -ForegroundColor Green
    } else {
        Write-Host "[*] Scheduled task '$TaskName' was not found or is already removed." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Error removing scheduled task: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
