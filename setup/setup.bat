@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem ============================================================
rem  SeedOfAnarky - Setup (Downloader + Unpacker)
rem
rem  What this does:
rem    1) Ensures optional .bat launchers are located in emu\ (not the root)
rem    2) Downloads the latest client package (or unpacks an existing archive)
rem    3) Extracts the archive to the repo root (next to emu\)
rem
rem  This script can be run from:
rem    - setup\setup.bat  (initial distribution)
rem    - setup.bat        (after it copies itself to root)
rem ============================================================

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%.") do set "SCRIPT_DIR=%%~fI\"

rem If running from a folder named "setup", root is the parent; otherwise script is already in root.
set "ROOT_DIR=%SCRIPT_DIR%"
if /i "%SCRIPT_DIR:~-6%"=="setup\" (
  for %%I in ("%SCRIPT_DIR%..") do set "ROOT_DIR=%%~fI\"
)

set "SETUP_DIR=%ROOT_DIR%setup\"

pushd "%ROOT_DIR%" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Could not access root folder: "%ROOT_DIR%"
  echo.
  pause
  exit /b 1
)

if not exist "%ROOT_DIR%emu\" (
  echo [ERROR] Missing expected folder: "%ROOT_DIR%emu\"
  echo [INFO] Place this repo folder so it contains an "emu" directory.
  echo.
  pause
  exit /b 1
)

rem If executed from setup\setup.bat, copy this script to root for future runs.
if /i "%SCRIPT_DIR:~-6%"=="setup\" (
  copy /y "%~f0" "%ROOT_DIR%setup.bat" >nul 2>&1
)

call :move_setup_bats_to_emu
call :main

set "RC=%errorlevel%"
popd >nul 2>&1
exit /b %RC%

:move_setup_bats_to_emu
if not exist "%SETUP_DIR%" exit /b 0

for %%F in ("%SETUP_DIR%*.bat") do (
  if /i not "%%~nxF"=="setup.bat" (
    rem Keep SOA_Launcher.bat in the root; move everything else into emu\.
    if /i "%%~nxF"=="SOA_Launcher.bat" (
      move /y "%%~fF" "%ROOT_DIR%" >nul 2>&1
    ) else (
      if exist "%ROOT_DIR%emu\\" (
        move /y "%%~fF" "%ROOT_DIR%emu\\" >nul 2>&1
      )
    )
  )
)
exit /b 0

:main
set "CLIENT_DIR=%ROOT_DIR%Client"
set "SERVER_DIR=%ROOT_DIR%Server"

set "HAS_ANY=0"
if exist "%CLIENT_DIR%\" set "HAS_ANY=1"
if exist "%SERVER_DIR%\" set "HAS_ANY=1"

echo ============================================================
echo   SOA Hytale Emu - Setup
echo ============================================================
echo Root: "%ROOT_DIR%"
echo.

if "%HAS_ANY%"=="1" (
  echo Detected existing folders:
  if exist "%CLIENT_DIR%\" echo   - Client\
  if exist "%SERVER_DIR%\" echo   - Server\
  echo.
)

choice /C DU /N /M "Choose: [D]ownload latest files or just [U]npack existing archive? "
set "ACTION=%errorlevel%"
echo.

call :load_config

set "CACHE_DIR=%ROOT_DIR%setup_cache"
set "DOWNLOAD_DIR=%CACHE_DIR%\downloads"
set "TOOLS_DIR=%CACHE_DIR%\tools"

if not exist "%DOWNLOAD_DIR%" mkdir "%DOWNLOAD_DIR%" >nul 2>&1
if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%" >nul 2>&1

if "%ACTION%"=="1" goto :action_download
goto :action_unpack

:action_download
set "ARCHIVE_PATH="
echo [INFO] Downloading latest package...
echo   URL : !DOWNLOAD_URL!
echo   To  : "%DOWNLOAD_DIR%"
echo.

set "DL_RC=0"
pushd "%DOWNLOAD_DIR%" >nul 2>&1
if errorlevel 1 (
  set "DL_RC=1"
) else (
  where curl.exe >nul 2>&1
  if !errorlevel!==0 (
    rem Download to a .part file so a failed download doesn't break unpack fallback.
    curl.exe -L --fail --retry 3 --retry-delay 2 -C - -o "latest.7z.part" "!DOWNLOAD_URL!"
    set "DL_RC=!errorlevel!"
  ) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "$u='!DOWNLOAD_URL!'; $p=Join-Path '%DOWNLOAD_DIR%' 'latest.7z.part';" ^
      "try { Invoke-WebRequest -Uri $u -OutFile $p -ErrorAction Stop; exit 0 } catch { exit 1 }"
    set "DL_RC=!errorlevel!"
  )

  if "!DL_RC!"=="0" (
    move /y "latest.7z.part" "latest.7z" >nul 2>&1
  )
  popd >nul 2>&1
)

if not "%DL_RC%"=="0" goto :download_failed_fallback

set "ARCHIVE_PATH=%DOWNLOAD_DIR%\latest.7z"
if not exist "%ARCHIVE_PATH%" goto :download_failed_fallback

echo [OK] Downloaded: "%ARCHIVE_PATH%"
echo.
goto :after_archive_selected

:download_failed_fallback
echo [WARN] Download failed. Falling back to unpack-only if an archive exists.
echo.
call :find_latest_archive "%DOWNLOAD_DIR%"
if defined ARCHIVE_PATH goto :after_archive_selected

echo [ERROR] No existing .7z archive found to unpack.
echo [INFO] Put a .7z in "%DOWNLOAD_DIR%" and re-run setup.
echo.
pause
exit /b 1

:action_unpack
call :find_latest_archive "%DOWNLOAD_DIR%"
if defined ARCHIVE_PATH goto :after_archive_selected

echo [INFO] No existing archive found. Attempting download instead...
echo.

set "ARCHIVE_PATH="
set "DL_RC=0"
pushd "%DOWNLOAD_DIR%" >nul 2>&1
if errorlevel 1 (
  set "DL_RC=1"
) else (
  where curl.exe >nul 2>&1
  if !errorlevel!==0 (
    curl.exe -L --fail --retry 3 --retry-delay 2 -C - -o "latest.7z.part" "!DOWNLOAD_URL!"
    set "DL_RC=!errorlevel!"
  ) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "$u='!DOWNLOAD_URL!'; $p=Join-Path '%DOWNLOAD_DIR%' 'latest.7z.part';" ^
      "try { Invoke-WebRequest -Uri $u -OutFile $p -ErrorAction Stop; exit 0 } catch { exit 1 }"
    set "DL_RC=!errorlevel!"
  )

  if "!DL_RC!"=="0" (
    move /y "latest.7z.part" "latest.7z" >nul 2>&1
  )
  popd >nul 2>&1
)

if not "%DL_RC%"=="0" (
  echo [ERROR] Download failed and no archive exists to unpack.
  echo.
  pause
  exit /b 1
)

set "ARCHIVE_PATH=%DOWNLOAD_DIR%\latest.7z"
if not exist "%ARCHIVE_PATH%" (
  echo [ERROR] Download finished but no archive file was found.
  echo.
  pause
  exit /b 1
)

echo [OK] Downloaded: "%ARCHIVE_PATH%"
echo.
goto :after_archive_selected

:after_archive_selected

call :ensure_extractor "%TOOLS_DIR%"
if errorlevel 1 (
  echo [ERROR] Could not find or download a 7z extractor.
  echo.
  pause
  exit /b 1
)

echo [INFO] Unpacking:
echo   Archive: "%ARCHIVE_PATH%"
echo   Target : "%ROOT_DIR%"
echo.

"%EXTRACTOR_EXE%" x -y "-o%ROOT_DIR%" "%ARCHIVE_PATH%"
if errorlevel 1 (
  echo.
  echo [ERROR] Unpack failed.
  echo.
  pause
  exit /b 1
)

echo.
echo [OK] Unpack complete.
if exist "%CLIENT_DIR%\" (
  echo [OK] Client folder present: "%CLIENT_DIR%"
) else (
  echo [WARN] Client folder not found after unpack.
)
if exist "%SERVER_DIR%\" (
  echo [OK] Server folder present: "%SERVER_DIR%"
) else (
  echo [WARN] Server folder not found after unpack.
)

echo.
echo Next:
echo   - Run SOA_Launcher.bat (GUI), or:
echo     - emu\\START_EMU.bat to start the emulator
echo     - emu\\START_GAME.bat to launch the game
echo.
pause
exit /b 0

:load_config
set "DOWNLOAD_URL="
set "CONFIG_FILE=%SETUP_DIR%config.txt"

if exist "%CONFIG_FILE%" (
  for /f "usebackq delims=" %%L in ("%CONFIG_FILE%") do (
    set "LINE=%%L"
    for /f "tokens=* delims= " %%Z in ("!LINE!") do set "LINE=%%Z"

    if not defined DOWNLOAD_URL (
      if not "!LINE!"=="" (
        if not "!LINE:~0,1!"=="#" if not "!LINE:~0,1!"==";" (
          for /f "tokens=1,* delims==" %%A in ("!LINE!") do (
            if /i "%%A"=="download_url" (
              set "DOWNLOAD_URL=%%B"
            ) else if /i "%%A"=="DOWNLOAD_URL" (
              set "DOWNLOAD_URL=%%B"
            ) else (
              set "DOWNLOAD_URL=!LINE!"
            )
          )
        )
      )
    )
  )
)

rem Fallback if config missing/empty.
if not defined DOWNLOAD_URL set "DOWNLOAD_URL=https://pixeldrain.com/u/KWoDM66y"

call :normalize_download_url

echo [INFO] Download source:
echo   !DOWNLOAD_URL!
echo.
exit /b 0

:normalize_download_url
set "URL=%DOWNLOAD_URL%"
for /f "tokens=* delims= " %%Z in ("!URL!") do set "URL=%%Z"

rem Trim surrounding quotes
if "!URL:~0,1!"=="\"" if "!URL:~-1!"=="\"" set "URL=!URL:~1,-1!"

rem Convert Pixeldrain share URL to direct download URL.
echo "!URL!" | findstr /i /c:"pixeldrain.com/u/" >nul
if not errorlevel 1 (
  set "PD_ID="
  for /f "tokens=5 delims=/" %%A in ("!URL!") do set "PD_ID=%%A"
  for /f "tokens=1 delims=?" %%A in ("!PD_ID!") do set "PD_ID=%%A"
  if defined PD_ID set "URL=https://pixeldrain.com/api/file/!PD_ID!?download"
)

rem If already using Pixeldrain API file URL, ensure ?download is present.
echo "!URL!" | findstr /i /c:"pixeldrain.com/api/file/" >nul
if not errorlevel 1 (
  echo "!URL!" | findstr /i /c:"?download" >nul
  if errorlevel 1 set "URL=!URL!?download"
)

set "DOWNLOAD_URL=!URL!"
exit /b 0

:find_latest_archive
set "ARCHIVE_PATH="
set "SEARCH_DIR=%~1"
for /f "delims=" %%F in ('dir /b /a:-d /o-d /t:w "%SEARCH_DIR%\*" 2^>nul ^| findstr /i /e ".7z .zip"') do (
  set "ARCHIVE_PATH=%SEARCH_DIR%\%%F"
  goto :find_latest_archive_done
)
:find_latest_archive_done
exit /b 0

:ensure_extractor
set "TOOLS_DIR=%~1"
set "EXTRACTOR_EXE="

rem Prefer installed 7-Zip if present
if exist "%ProgramFiles%\\7-Zip\\7z.exe" set "EXTRACTOR_EXE=%ProgramFiles%\\7-Zip\\7z.exe"
if not defined EXTRACTOR_EXE if exist "%ProgramFiles(x86)%\\7-Zip\\7z.exe" set "EXTRACTOR_EXE=%ProgramFiles(x86)%\\7-Zip\\7z.exe"

rem Fallback to 7zr in cache tools dir
if not defined EXTRACTOR_EXE if exist "%TOOLS_DIR%\\7zr.exe" set "EXTRACTOR_EXE=%TOOLS_DIR%\\7zr.exe"
if defined EXTRACTOR_EXE exit /b 0

echo [INFO] 7-Zip not found. Downloading portable extractor (7zr.exe)...
echo.

set "SEVENZIP_URL=https://www.7-zip.org/a/7zr.exe"
where curl.exe >nul 2>&1
if %errorlevel%==0 (
  curl.exe -L --fail --retry 3 --retry-delay 2 -o "%TOOLS_DIR%\\7zr.exe" "%SEVENZIP_URL%"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$u='%SEVENZIP_URL%'; $p='%TOOLS_DIR%\\7zr.exe';" ^
    "try { Invoke-WebRequest -Uri $u -OutFile $p -ErrorAction Stop; exit 0 } catch { exit 1 }"
)

if errorlevel 1 exit /b 1
if not exist "%TOOLS_DIR%\\7zr.exe" exit /b 1

set "EXTRACTOR_EXE=%TOOLS_DIR%\\7zr.exe"
exit /b 0
