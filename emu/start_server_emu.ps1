param(
    [ValidateSet(1, 2)]
    [int]$Mode = 2,
    [int]$Port = 443,
    [switch]$NoHostsCleanup,
    [switch]$CheckDepsOnly
)

# Unified EMU2 server launcher.
# This adapts the old Server-side emulator launcher flow to EMU2:
# - Adds hosts redirects (hytale.com domains -> 127.0.0.1)
# - Ensures certs exist
# - Keeps emu-truststore.jks in sync with server.crt
# - Syncs Server\certs from emu\certs (emu is source-of-truth)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# PYTHON DEPENDENCIES (Python 3.8+ + cryptography + cffi)
# ============================================================

$MinPythonVersion = [Version]'3.8'

function Refresh-ProcessPathFromRegistry {
    # If an installer updated PATH, this process won't see it unless we refresh.
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $proc = [Environment]::GetEnvironmentVariable('Path', 'Process')
    $parts = @()
    if ($machine) { $parts += $machine }
    if ($user) { $parts += $user }
    if ($proc) { $parts += $proc }
    if ($parts.Count -gt 0) {
        $env:Path = ($parts -join ';')
    }
}

function Try-GetPythonInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Exe,
        [string[]]$PrefixArgs = @()
    )

    try {
        $out = & $Exe @PrefixArgs -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null
    } catch {
        return $null
    }

    if ($LASTEXITCODE -ne 0) { return $null }

    $verText = ($out | Out-String).Trim()
    if (-not $verText) { return $null }

    $ver = $null
    try { $ver = [Version]$verText } catch { return $null }

    $display = $Exe
    if ($PrefixArgs -and $PrefixArgs.Count -gt 0) {
        $display = ($display + ' ' + ($PrefixArgs -join ' '))
    }

    return [pscustomobject]@{
        Exe     = $Exe
        Args    = @($PrefixArgs)
        Version = $ver
        Display = $display
    }
}

function Resolve-PythonInvocation {
    param(
        [Version]$MinVersion = [Version]'3.8'
    )

    $candidates = New-Object System.Collections.Generic.List[object]

    # Prefer the Windows Python launcher if present (helps when multiple Pythons exist).
    $candidates.Add([pscustomobject]@{ Exe = 'py'; Args = @('-3') }) | Out-Null
    $candidates.Add([pscustomobject]@{ Exe = 'python'; Args = @() }) | Out-Null

    $paths = @()
    if ($env:LOCALAPPDATA) {
        $paths += @(Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\python.exe') -ErrorAction SilentlyContinue)
    }
    if ($env:ProgramFiles) {
        $paths += @(Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Python*\python.exe') -ErrorAction SilentlyContinue)
    }
    if (${env:ProgramFiles(x86)}) {
        $paths += @(Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Python*\python.exe') -ErrorAction SilentlyContinue)
    }

    foreach ($p in $paths) {
        if (-not $p) { continue }
        $candidates.Add([pscustomobject]@{ Exe = $p.FullName; Args = @() }) | Out-Null
    }

    $valid = @()
    foreach ($c in $candidates) {
        if (-not $c -or -not $c.Exe) { continue }
        $info = Try-GetPythonInfo -Exe $c.Exe -PrefixArgs $c.Args
        if ($info -and $info.Version -ge $MinVersion) {
            $valid += $info
        }
    }

    if (-not $valid -or $valid.Count -eq 0) { return $null }
    return ($valid | Sort-Object Version -Descending | Select-Object -First 1)
}

function Ensure-Pip {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PyExe,
        [string[]]$PyArgs = @()
    )

    try {
        $null = & $PyExe @PyArgs -m pip --version 2>$null
        if ($LASTEXITCODE -eq 0) { return $true }
    } catch { }

    try {
        $null = & $PyExe @PyArgs -m ensurepip --upgrade 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Test-PythonModule {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PyExe,
        [string[]]$PyArgs = @(),
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )
    try {
        $null = & $PyExe @PyArgs -c ("import {0}" -f $ModuleName) 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Test-PythonSnippet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PyExe,
        [string[]]$PyArgs = @(),
        [Parameter(Mandatory = $true)]
        [string]$Code
    )
    try {
        $null = & $PyExe @PyArgs -c $Code 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Ensure-PythonAndDeps {
    param(
        [Version]$MinVersion = [Version]'3.8'
    )

    Refresh-ProcessPathFromRegistry
    $py = Resolve-PythonInvocation -MinVersion $MinVersion

    if (-not $py) {
        Write-Host "[DEPS] Python $MinVersion+ is required to run the emulator server." -ForegroundColor Yellow

        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            $resp = Read-Host "Install Python automatically now using winget? (Y/N)"
            if ($resp -match '^[Yy]') {
                Write-Host "[DEPS] Installing Python via winget (this may take a minute)..." -ForegroundColor Yellow
                $installOk = $false
                $candidateIds = @(
                    'Python.Python.3.13',
                    'Python.Python.3.12',
                    'Python.Python.3.11',
                    'Python.Python.3.10',
                    'Python.Python.3.9',
                    'Python.Python.3.8'
                )

                foreach ($id in $candidateIds) {
                    Write-Host "[DEPS] Attempting: winget install $id" -ForegroundColor Yellow
                    & winget install -e --id $id --scope user --accept-package-agreements --accept-source-agreements 2>&1 | Out-Host
                    if ($LASTEXITCODE -eq 0) {
                        $installOk = $true
                        break
                    }
                }

                if (-not $installOk) {
                    Write-Host "[ERROR] winget failed to install Python." -ForegroundColor Red
                    Write-Host "       Install Python manually from: https://www.python.org/downloads/windows/" -ForegroundColor Red
                    return $null
                }

                Refresh-ProcessPathFromRegistry
                $py = Resolve-PythonInvocation -MinVersion $MinVersion
            }
        }

        if (-not $py) {
            Write-Host "[ERROR] Python still not detected." -ForegroundColor Red
            Write-Host "       Install Python $MinVersion+ and re-run this launcher." -ForegroundColor Red
            Write-Host "       Manual download: https://www.python.org/downloads/windows/" -ForegroundColor Red
            return $null
        }
    }

    if (-not (Ensure-Pip -PyExe $py.Exe -PyArgs $py.Args)) {
        Write-Host "[ERROR] pip is missing or could not be enabled for: $($py.Display)" -ForegroundColor Red
        Write-Host "       Reinstall Python (include pip) and re-run." -ForegroundColor Red
        return $null
    }

    if (-not (Test-PythonModule -PyExe $py.Exe -PyArgs $py.Args -ModuleName 'cffi')) {
        Write-Host "[DEPS] Installing required Python package: cffi" -ForegroundColor Yellow
        & $py.Exe @($py.Args) -m pip install --user --upgrade cffi 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Failed to install 'cffi' (exit=$LASTEXITCODE)." -ForegroundColor Red
            Write-Host "       Try running:" -ForegroundColor Red
            Write-Host "       $($py.Display) -m pip install cffi" -ForegroundColor Red
            return $null
        }
    }

    if (-not (Test-PythonModule -PyExe $py.Exe -PyArgs $py.Args -ModuleName 'cryptography')) {
        Write-Host "[DEPS] Installing required Python package: cryptography" -ForegroundColor Yellow
        & $py.Exe @($py.Args) -m pip install --user --upgrade cryptography 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Failed to install 'cryptography' (exit=$LASTEXITCODE)." -ForegroundColor Red
            Write-Host "       Try running:" -ForegroundColor Red
            Write-Host "       $($py.Display) -m pip install cryptography" -ForegroundColor Red
            return $null
        }
    }

    $cryptoProbe = "from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key"
    if (-not (Test-PythonSnippet -PyExe $py.Exe -PyArgs $py.Args -Code $cryptoProbe)) {
        Write-Host "[DEPS] Repairing Python crypto packages (cryptography/cffi)..." -ForegroundColor Yellow
        & $py.Exe @($py.Args) -m pip install --user --upgrade --force-reinstall cffi cryptography 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Failed to repair Python crypto packages (exit=$LASTEXITCODE)." -ForegroundColor Red
            Write-Host "       Try running:" -ForegroundColor Red
            Write-Host "       $($py.Display) -m pip install --upgrade --force-reinstall cffi cryptography" -ForegroundColor Red
            return $null
        }
        if (-not (Test-PythonSnippet -PyExe $py.Exe -PyArgs $py.Args -Code $cryptoProbe)) {
            Write-Host "[ERROR] cryptography is installed but still cannot import required modules." -ForegroundColor Red
            Write-Host "       Try reinstalling Python (and ensure pip works), then re-run." -ForegroundColor Red
            return $null
        }
    }

    return $py
}

$Python = Ensure-PythonAndDeps -MinVersion $MinPythonVersion
if (-not $Python) { exit 1 }

if ($CheckDepsOnly) {
    Write-Host "[OK] Python dependencies look good: $($Python.Display) (v$($Python.Version))" -ForegroundColor Green
    exit 0
}

# ============================================================
# ADMIN CHECK (hosts file needs admin, port 443 may need admin)
# ============================================================

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-Mode", $Mode, "-Port", $Port)
    if ($NoHostsCleanup) { $argList += "-NoHostsCleanup" }
    Start-Process PowerShell -Verb RunAs -ArgumentList $argList
    exit
}

# ============================================================
# PATHS
# ============================================================

$EmuDir = $PSScriptRoot
$GameDir = Split-Path $EmuDir -Parent
$ServerDir = Join-Path $GameDir 'Server'

$EmuServerPy = Join-Path $EmuDir 'server.py'
$EmuGenerateCertsPy = Join-Path $EmuDir 'generate_certs.py'
$EmuConfigPath = Join-Path $EmuDir 'config.json'
$EmuEndpointsPath = Join-Path $EmuDir 'endpoints.json'

$EmuCertsDir = Join-Path $EmuDir 'certs'
$ServerCertsDir = Join-Path $ServerDir 'certs'

$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$MarkerStart = '# === SeedOfAnarky EMU START ==='
$MarkerEnd = '# === SeedOfAnarky EMU END ==='

if (-not (Test-Path $EmuServerPy)) { throw "Missing emulator server: $EmuServerPy" }
if (-not (Test-Path $EmuConfigPath)) { throw "Missing emulator config: $EmuConfigPath" }

# ============================================================
# HELPERS
# ============================================================

function Remove-EmuHostsBlock {
    param([switch]$BestEffort)

    if (-not (Test-Path $HostsFile)) { return $false }
    $content = Get-Content $HostsFile -Raw -ErrorAction SilentlyContinue
    if (-not $content) { return $false }
    if ($content -notmatch [regex]::Escape($MarkerStart)) { return $false }

    $pattern = "(?s)$([regex]::Escape($MarkerStart)).*?$([regex]::Escape($MarkerEnd))\r?\n?"
    $newContent = $content -replace $pattern, ''
    $maxAttempts = 40
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Set-Content -Path $HostsFile -Value $newContent -NoNewline -Encoding ASCII
            $null = ipconfig /flushdns 2>&1
            return $true
        } catch {
            if ($attempt -ge $maxAttempts) {
                if ($BestEffort) {
                    Write-Host "[WARN] Failed to update hosts file (locked by another process). Leaving redirects in place." -ForegroundColor Yellow
                    Write-Host "       Hosts path: $HostsFile" -ForegroundColor Yellow
                    return $false
                }
                throw
            }
            Start-Sleep -Milliseconds 250
        }
    }
    return $false
}

function Add-EmuHostsBlock {
    param([string[]]$Domains)

    if (-not $Domains -or $Domains.Count -eq 0) {
        throw "No domains provided for hosts redirects"
    }

    # Refresh existing block if present.
    Remove-EmuHostsBlock | Out-Null

    $domainsUnique = @(
        $Domains |
        Where-Object { $_ -and $_.Trim() } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
    )

    $block = "`n$MarkerStart`n"
    foreach ($d in $domainsUnique) {
        $block += "127.0.0.1 $d`n"
        $block += "127.0.0.1 www.$d`n"
    }
    $block += "$MarkerEnd`n"

    $maxAttempts = 40
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Add-Content -Path $HostsFile -Value $block -Encoding ASCII
            $null = ipconfig /flushdns 2>&1
            return
        } catch {
            if ($attempt -ge $maxAttempts) {
                throw
            }
            Start-Sleep -Milliseconds 250
        }
    }
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = [System.IO.File]::ReadAllText($Path)
    # Strip BOM if present
    $raw = $raw -replace '^\uFEFF', ''
    return $raw | ConvertFrom-Json
}

function Find-Keytool {
    $keytool = (Get-Command keytool -ErrorAction SilentlyContinue)
    if ($keytool) { return $keytool.Source }

    $javaHome = $env:JAVA_HOME
    if ($javaHome) {
        $p = Join-Path $javaHome 'bin\keytool.exe'
        if (Test-Path $p) { return $p }
    }

    $java = (Get-Command java -ErrorAction SilentlyContinue)
    if ($java) {
        $javaDir = Split-Path (Split-Path $java.Source -Parent) -Parent
        $p = Join-Path $javaDir 'bin\keytool.exe'
        if (Test-Path $p) { return $p }
    }

    return $null
}

function Ensure-EmuTruststoreFresh {
    param(
        [string]$CertPath,
        [string]$TruststorePath
    )

    if (-not (Test-Path $CertPath)) { throw "Missing TLS cert: $CertPath" }

    $certMtime = (Get-Item $CertPath).LastWriteTimeUtc
    if ((Test-Path $TruststorePath) -and ((Get-Item $TruststorePath).LastWriteTimeUtc -ge $certMtime)) {
        return
    }

    $keytoolPath = Find-Keytool
    if (-not $keytoolPath) {
        Write-Host "[WARN] keytool not found; cannot refresh emu-truststore.jks" -ForegroundColor Yellow
        Write-Host "       If you start HytaleServer without the Python wrapper, SSL may fail unless you install the cert into Java's truststore." -ForegroundColor Yellow
        return
    }

    if (Test-Path $TruststorePath) { Remove-Item $TruststorePath -Force }

    # keytool writes informational messages to stderr; avoid treating them as terminating errors.
    $oldEap = $ErrorActionPreference
    $keytoolOutput = $null
    try {
        $ErrorActionPreference = 'Continue'
        $keytoolOutput = & $keytoolPath -import -noprompt -trustcacerts -alias hytale-emu `
            -file $CertPath `
            -keystore $TruststorePath `
            -storepass changeit 2>&1
    } finally {
        $ErrorActionPreference = $oldEap
    }

    if ($LASTEXITCODE -ne 0) {
        $outText = ($keytoolOutput | Out-String).Trim()
        throw "Failed to create truststore: $TruststorePath`n$keytoolPath output:`n$outText"
    }
}

function Ensure-EmuCertTrustedForWindowsClient {
    param([string]$CertPath)

    if (-not (Test-Path $CertPath)) { throw "Missing TLS cert: $CertPath" }

    # HytaleClient.exe uses Windows cert validation (Schannel). If the EMU TLS cert isn't trusted,
    # the client fails early while fetching JWKS.
    $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
    $thumb = $certObj.Thumbprint

    $storePath = 'Cert:\CurrentUser\Root'
    $already = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
    if ($already) {
        Write-Host "[CERT] Windows trust already contains EMU TLS cert: $thumb" -ForegroundColor Green
        return
    }

    $imported = $false

    # Prefer certutil: it's reliable and avoids occasional Import-Certificate hangs.
    $certutil = Get-Command certutil.exe -ErrorAction SilentlyContinue
    if ($certutil) {
        $out = & certutil.exe -user -addstore Root $CertPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            $outText = ($out | Out-String).Trim()
            throw "certutil failed to add cert to CurrentUser Root store (exit=$LASTEXITCODE)`n$outText"
        }
        $imported = $true
    } else {
        $importCmd = Get-Command Import-Certificate -ErrorAction SilentlyContinue
        if ($importCmd) {
            Import-Certificate -FilePath $CertPath -CertStoreLocation $storePath | Out-Null
            $imported = $true
        }
    }

    if (-not $imported) {
        throw "Unable to import cert into Windows trust store (Import-Certificate and certutil.exe not found)"
    }

    Write-Host "[CERT] Installed EMU TLS cert into Windows CurrentUser Trusted Root store: $thumb" -ForegroundColor Green
}

function Sync-CertsToServer {
    if (-not (Test-Path $ServerDir)) { return }
    if (-not (Test-Path $EmuCertsDir)) { return }

    New-Item -ItemType Directory -Path $ServerCertsDir -Force | Out-Null

    $files = @(
        'server.crt',
        'server.key',
        'emu-truststore.jks',
        'ed25519_private.pem',
        'ed25519_public.pem'
    )

    foreach ($name in $files) {
        $src = Join-Path $EmuCertsDir $name
        if (-not (Test-Path $src)) { continue }
        $dst = Join-Path $ServerCertsDir $name
        Copy-Item -Path $src -Destination $dst -Force
    }
}

# ============================================================
# HOSTS REDIRECTS
# ============================================================

$didAddHosts = $false

try {
    $domains = @()
    $endpoints = Read-JsonFile $EmuEndpointsPath
    if ($endpoints -and $endpoints.redirect_domains) {
        $domains = @($endpoints.redirect_domains | ForEach-Object { $_.ToString() })
    }
    if (-not $domains -or $domains.Count -eq 0) {
        $cfg = Read-JsonFile $EmuConfigPath
        if ($cfg -and $cfg.server -and $cfg.server.domains) {
            $domains = @($cfg.server.domains | ForEach-Object { $_.ToString() })
        }
    }

    Write-Host "[HOSTS] Redirecting domains to 127.0.0.1" -ForegroundColor Cyan
    Add-EmuHostsBlock -Domains $domains
    $didAddHosts = $true

    # ============================================================
    # CERTS / TRUSTSTORE
    # ============================================================

    New-Item -ItemType Directory -Path $EmuCertsDir -Force | Out-Null
    $required = @('server.crt', 'server.key', 'ed25519_private.pem', 'ed25519_public.pem')
    $missing = @($required | Where-Object { -not (Test-Path (Join-Path $EmuCertsDir $_)) })

    if ($missing.Count -gt 0) {
        $present = @($required | Where-Object { Test-Path (Join-Path $EmuCertsDir $_) })
        if ($present.Count -gt 0) {
            throw "Partial cert set in $EmuCertsDir (present: $($present -join ', '); missing: $($missing -join ', ')). Run: $($Python.Display) `"$EmuGenerateCertsPy`" and overwrite to regenerate all."
        }

        Write-Host "[CERT] Generating emulator certificates..." -ForegroundColor Yellow
        & $Python.Exe @($Python.Args) $EmuGenerateCertsPy
        if ($LASTEXITCODE -ne 0) { throw "Certificate generation failed" }
    }

    $emuCert = Join-Path $EmuCertsDir 'server.crt'
    $emuTruststore = Join-Path $EmuCertsDir 'emu-truststore.jks'
    Ensure-EmuTruststoreFresh -CertPath $emuCert -TruststorePath $emuTruststore
    Ensure-EmuCertTrustedForWindowsClient -CertPath $emuCert

    Sync-CertsToServer

    # ============================================================
    # START EMULATOR
    # ============================================================

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  Starting EMU2 Server" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Working dir: $EmuDir" -ForegroundColor Gray
    Write-Host "  Command: $($Python.Display) server.py --mode $Mode --port $Port" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
    Write-Host ""

    Push-Location $EmuDir
    try {
        & $Python.Exe @($Python.Args) $EmuServerPy --mode $Mode --port $Port
    } finally {
        Pop-Location
    }
} finally {
    if ($didAddHosts) {
        if (-not $NoHostsCleanup) {
            Write-Host ""
            Write-Host "[HOSTS] Cleaning up hosts redirects..." -ForegroundColor Cyan
            Remove-EmuHostsBlock -BestEffort | Out-Null
        } else {
            Write-Host ""
            Write-Host "[HOSTS] Leaving hosts redirects in place (NoHostsCleanup set)" -ForegroundColor Cyan
        }
    }
}
