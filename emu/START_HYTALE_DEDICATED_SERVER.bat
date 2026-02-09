@echo off
setlocal
title Hytale Server - Interactive Mode
color 0B

echo ============================================================
echo   Hytale Server - Interactive Mode
echo ============================================================
echo.

cd /d "%~dp0"

if not exist "%~dp0START_SERVER.bat" (
    echo [ERROR] Missing: "%~dp0START_SERVER.bat"
    echo [INFO] Make sure this file lives inside the "emu" folder.
    echo.
    pause
    exit /b 1
)

call "%~dp0START_SERVER.bat"
exit /b %errorlevel%

