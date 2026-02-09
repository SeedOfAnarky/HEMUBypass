@echo off
title SeedOfAnarky Emulator Server
color 0A

echo ============================================================
echo   SeedOfAnarky EMULATOR SERVER
echo ============================================================
echo.

cd /d "%~dp0"

:: Use the PowerShell launcher to handle:
:: - admin elevation
:: - hosts redirects
:: - cert generation (if missing)
:: - truststore refresh (emu-truststore.jks)
:: - syncing Server\certs from emu\certs
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_server_emu.ps1" -Mode 2 -Port 443

pause

