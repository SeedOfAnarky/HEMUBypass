@echo off
title SeedOfAnarky Emulator - Launch Game
color 0E

echo ============================================================
echo   SeedOfAnarky EMULATOR - LAUNCH GAME
echo ============================================================
echo.

:: Check for admin (needed for hosts file)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Needs Administrator privileges for hosts file.
    echo [!] Right-click and "Run as Administrator"
    echo.
    pause
    exit /b 1
)

cd /d "%~dp0"

echo Make sure START_EMU.bat is running in another window!
echo.

PowerShell -NoProfile -ExecutionPolicy Bypass -File "%~dp0launcher.ps1" -Mode 2
