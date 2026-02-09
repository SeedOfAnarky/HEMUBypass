@echo off
setlocal
title SeedOfAnarky Emulator Server
color 0A

cd /d "%~dp0"
if not exist "%~dp0START_EMU.bat" (
    echo [ERROR] Missing: "%~dp0START_EMU.bat"
    echo [INFO] Make sure this file lives inside the "emu" folder.
    echo.
    pause
    exit /b 1
)

call "%~dp0START_EMU.bat"
exit /b %errorlevel%

