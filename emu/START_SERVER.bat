@echo off
REM Hytale Server Launcher (Interactive Mode) - run from ./emu

echo ============================================================
echo   Hytale Server - Interactive Mode
echo ============================================================
echo.

cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8 or later.
    echo.
    pause
    exit /b 1
)

REM Run the server wrapper (starts ..\Server\HytaleServer.jar)
python "%~dp0run_hytale_server.py"

if errorlevel 1 (
    echo.
    echo [ERROR] Server exited with error
    pause
    exit /b 1
)

echo.
echo Server stopped normally.
pause

