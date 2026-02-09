@echo off
setlocal
cd /d "%~dp0"

REM Root stub: the real GUI launcher lives in emu\
if not exist "%~dp0emu\\SOA_Launcher.vbs" (
    echo [ERROR] Missing: "%~dp0emu\\SOA_Launcher.vbs"
    echo [INFO] Make sure the launcher files exist in the "emu" folder.
    echo.
    pause
    exit /b 1
)

REM Launch the GUI elevated without leaving a visible console window.
REM If scripts are blocked, right-click SOA_Launcher.bat and Run as Administrator.
"%SystemRoot%\\System32\\wscript.exe" "%~dp0emu\\SOA_Launcher.vbs"

