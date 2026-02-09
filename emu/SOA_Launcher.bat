@echo off
setlocal
cd /d "%~dp0"

REM Launch the GUI elevated without leaving a visible console window.
REM If scripts are blocked, right-click SOA_Launcher.bat and Run as Administrator.
"%SystemRoot%\\System32\\wscript.exe" "%~dp0SOA_Launcher.vbs"
