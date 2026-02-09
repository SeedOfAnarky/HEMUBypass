@echo off
setlocal
title SeedOfAnarky Emulator - Launch Game
color 0E

cd /d "%~dp0"
if not exist "%~dp0START_GAME.bat" (
    echo [ERROR] Missing: "%~dp0START_GAME.bat"
    echo [INFO] Make sure this file lives inside the "emu" folder.
    echo.
    pause
    exit /b 1
)

call "%~dp0START_GAME.bat"
exit /b %errorlevel%

