# SentinelPy IDS / IPS - Windows Autostart Registration Script
# Registers a Windows Scheduled Task with Highest (Administrator) privileges to run SentinelPy on startup.

param (
    [ValidateSet("background", "terminal")]
    [string]$Mode = "background",
    
    [ValidateSet("logon", "boot")]
    [string]$TriggerType = "logon"
)

$TaskName = "SentinelPy_IDS"
$ProjectDir = (Resolve-Path "$PSScriptRoot\..").Path
$MainScript = Join-Path $ProjectDir "main.py"

if (-not (Test-Path $MainScript)) {
    Write-Host "[!] Error: Could not locate main.py at $MainScript" -ForegroundColor Red
    pause
    exit 1
}

# Find Python executables
$PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python313\python.exe"
}
$PythonDir = Split-Path $PythonExe
$PythonwExe = Join-Path $PythonDir "pythonw.exe"

# Elevation check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[*] Requesting Administrator privileges to configure Task Scheduler..." -ForegroundColor Yellow
    $argsList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode $Mode -TriggerType $TriggerType"
    Start-Process powershell -Verb RunAs -ArgumentList $argsList
    exit
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  SENTINELPY IDS / IPS - AUTOSTART CONFIGURATION" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "Project Directory : $ProjectDir" -ForegroundColor Gray
Write-Host "Python Executable : $PythonExe" -ForegroundColor Gray
Write-Host "Execution Mode    : $Mode" -ForegroundColor Yellow
Write-Host "Trigger Event     : $TriggerType" -ForegroundColor Yellow
Write-Host ""

# Unregister any existing task first
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Configure Action
if ($Mode -eq "background") {
    $ExecPath = if (Test-Path $PythonwExe) { $PythonwExe } else { $PythonExe }
    $Action = New-ScheduledTaskAction -Execute $ExecPath -Argument "main.py run" -WorkingDirectory $ProjectDir
} else {
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoExit -ExecutionPolicy Bypass -Command `"Set-Location '$ProjectDir'; & '$PythonExe' main.py run`"" `
        -WorkingDirectory $ProjectDir
}

# Configure Trigger & Principal
if ($TriggerType -eq "boot") {
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
} else {
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
}

$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

try {
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
    Write-Host "[+] SUCCESS: Scheduled Task '$TaskName' has been registered!" -ForegroundColor Green
    Write-Host "[+] SentinelPy will automatically start when you boot/login ($Mode mode)." -ForegroundColor Green
    Write-Host ""
    Write-Host "Quick Controls:" -ForegroundColor Cyan
    Write-Host "  Start task now : Start-ScheduledTask -TaskName `"$TaskName`"" -ForegroundColor Gray
    Write-Host "  Stop task      : Stop-ScheduledTask -TaskName `"$TaskName`"" -ForegroundColor Gray
    Write-Host "  Disable        : Run .\scripts\disable_autostart.ps1" -ForegroundColor Gray
} catch {
    Write-Host "[!] Failed to register scheduled task: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
