@echo off
title SentinelPy IDS Autostart Configuration
cd /d "%~dp0"

echo =======================================================
echo   SentinelPy IDS / IPS - Windows Autostart Setup
echo =======================================================
echo.
echo Select an option:
echo.
echo   [1] Silent Background Mode (Recommended)
echo       Runs quietly in the background on startup.
echo       Alerts sent to email/webhook, logged to database.
echo.
echo   [2] Visible Terminal Window Mode
echo       Opens an interactive terminal window on boot
echo       displaying the live SentinelPy monitoring feed.
echo.
echo   [3] Check Current Autostart Status
echo.
echo   [4] Disable / Remove Autostart
echo.
echo   [5] Exit
echo.
set /p choice="Enter your choice [1-5]: "

if "%choice%"=="1" (
    powershell.exe -ExecutionPolicy Bypass -File "%~dp0scripts\enable_autostart.ps1" -Mode background
) else if "%choice%"=="2" (
    powershell.exe -ExecutionPolicy Bypass -File "%~dp0scripts\enable_autostart.ps1" -Mode terminal
) else if "%choice%"=="3" (
    powershell.exe -NoProfile -Command "Get-ScheduledTask -TaskName 'SentinelPy_IDS' -ErrorAction SilentlyContinue | Format-List TaskName, State; pause"
) else if "%choice%"=="4" (
    powershell.exe -ExecutionPolicy Bypass -File "%~dp0scripts\disable_autostart.ps1"
) else (
    echo Exiting setup.
)
