param(
    [ValidateSet(1, 2)]
    [int]$Mode = 0,
    [string]$BaseUrl = 'https://sessions.SeedOfAnarky.fr',
    [string]$SessionsHost = 'sessions.SeedOfAnarky.fr',
    [string]$Scope = 'hytale:client',
    [string]$LogPath = $(Join-Path $PSScriptRoot 'emu_full_trace.log'),
    [string]$Username,
    [string]$Password,
    [string]$EmuServerUrl = 'https://127.0.0.1'
)

# ============================================================
# ADMIN CHECK
# ============================================================

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$($MyInvocation.MyCommand.Path)`"")
    if ($Mode -ne 0) { $argList += "-Mode"; $argList += $Mode }
    Start-Process PowerShell -Verb RunAs -ArgumentList $argList
    exit
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# SSL CERT BYPASS (for self-signed emu cert in Mode 2)
# ============================================================

Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ============================================================
# PATHS
# ============================================================

$EmuDir = $PSScriptRoot
$GameDir = Split-Path $EmuDir -Parent
$ClientDir = Join-Path $GameDir 'Client'
$ClientExe = Join-Path $ClientDir 'HytaleClient.exe'
$AppDir = $GameDir
$UserDir = Join-Path $ClientDir 'UserData'

# ============================================================
# JAVA TRUSTSTORE (for HytaleServer JWKS fetch)
# ============================================================

$EmuCertPath = Join-Path $PSScriptRoot 'certs\server.crt'
$EmuTrustStore = Join-Path $PSScriptRoot 'certs\emu-truststore.jks'
$EmuTrustStorePass = 'changeit'
$EmuTrustStoreAlias = 'hytale-emu'

# ============================================================
# HOSTS FILE
# ============================================================

$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$MarkerStart = '# === SeedOfAnarky EMU START ==='
$MarkerEnd = '# === SeedOfAnarky EMU END ==='

$EndpointsPath = Join-Path $PSScriptRoot 'endpoints.json'
$BaseUrlWasSet = $PSBoundParameters.ContainsKey('BaseUrl')
$EmuServerUrlWasSet = $PSBoundParameters.ContainsKey('EmuServerUrl')
$SessionsHostWasSet = $PSBoundParameters.ContainsKey('SessionsHost')

$RedirectDomains = @(
    'sessions.SeedOfAnarky.fr',
    'account-data.SeedOfAnarky.fr',
    'api.SeedOfAnarky.fr', 
    'cdn.SeedOfAnarky.fr',
    'telemetry.SeedOfAnarky.fr',
    'SeedOfAnarky.fr'
)

if (Test-Path $EndpointsPath) {
    $endpointJson = [System.IO.File]::ReadAllText($EndpointsPath)
    # Strip BOM if present
    $endpointJson = $endpointJson -replace '^\uFEFF', ''
    # Fallback detection if JSON parsing fails
    $useProd = $false
    if ($endpointJson -match '"use_production"\s*:\s*true') { $useProd = $true }

    try {
        $endpointCfg = $endpointJson | ConvertFrom-Json
        try { $useProd = [bool]$endpointCfg.use_production } catch { }
        $prodCfg = $null
        if ($useProd -and $endpointCfg.production_config) { $prodCfg = $endpointCfg.production_config }

        # Resolve base (SeedOfAnarky) domains from endpoints.json
        $baseDomains = @()
        if ($endpointCfg.redirect_domains) {
            $baseDomains = @($endpointCfg.redirect_domains | ForEach-Object { $_.ToString() })
        } else {
            $baseDomains = @(
                'sessions.SeedOfAnarky.fr',
                'account-data.SeedOfAnarky.fr',
                'api.SeedOfAnarky.fr',
                'cdn.SeedOfAnarky.fr',
                'telemetry.SeedOfAnarky.fr',
                'SeedOfAnarky.fr'
            )
        }

        if ($useProd) {
            # Production config takes precedence for host/base_url
            if ($prodCfg) {
                if ($prodCfg.sessions_host -and -not $SessionsHostWasSet) {
                    $SessionsHost = [string]$prodCfg.sessions_host
                }
                if ($prodCfg.base_url -and -not $BaseUrlWasSet) {
                    $BaseUrl = [string]$prodCfg.base_url
                }
                if ($prodCfg.emu_server_url -and -not $EmuServerUrlWasSet) {
                    $EmuServerUrl = [string]$prodCfg.emu_server_url
                }
            }

            # Include BOTH base (SeedOfAnarky) + production (hytale) domains
            $prodDomains = @()
            if ($prodCfg -and $prodCfg.redirect_domains) {
                $prodDomains = @($prodCfg.redirect_domains | ForEach-Object { $_.ToString() })
            } else {
                # Derive by swapping SeedOfAnarky -> hytale
                $prodDomains = @($baseDomains | ForEach-Object { $_.Replace('SeedOfAnarky.fr', 'hytale.com') })
            }
            $RedirectDomains = @($baseDomains + $prodDomains) | Sort-Object -Unique
        } else {
            if ($endpointCfg.sessions_host -and -not $SessionsHostWasSet) {
                $SessionsHost = [string]$endpointCfg.sessions_host
            }
            if ($endpointCfg.base_url -and -not $BaseUrlWasSet) {
                $BaseUrl = [string]$endpointCfg.base_url
            }
            $RedirectDomains = @($baseDomains)
        }

        if ($endpointCfg.emu_server_url -and -not $EmuServerUrlWasSet) {
            $EmuServerUrl = [string]$endpointCfg.emu_server_url
        }

        $extraDomains = @()
        if ($endpointCfg.extra_redirect_domains) {
            $extraDomains += @($endpointCfg.extra_redirect_domains | ForEach-Object { $_.ToString() })
        }
        if ($prodCfg -and $prodCfg.extra_redirect_domains) {
            $extraDomains += @($prodCfg.extra_redirect_domains | ForEach-Object { $_.ToString() })
        }
        if ($extraDomains.Count -gt 0) {
            $RedirectDomains += $extraDomains
            $RedirectDomains = $RedirectDomains | Sort-Object -Unique
        }

        if (-not $BaseUrlWasSet -and -not $endpointCfg.base_url -and -not ($prodCfg -and $prodCfg.base_url) -and $SessionsHost -and $SessionsHost -ne 'sessions.SeedOfAnarky.fr') {
            $BaseUrl = "https://$SessionsHost"
        }
        Write-Host "[CONFIG] Loaded endpoints from $EndpointsPath" -ForegroundColor Cyan
        Write-Host "[CONFIG] use_production = $useProd" -ForegroundColor Cyan
        Write-Host "[CONFIG] sessions_host = $SessionsHost" -ForegroundColor Cyan
        Write-Host "[CONFIG] redirect_domains = $($RedirectDomains -join ', ')" -ForegroundColor Cyan
    } catch {
        Write-Host "[WARN] Failed to parse endpoints.json. Using fallback." -ForegroundColor Yellow
        if ($useProd) {
            if (-not $SessionsHostWasSet) { $SessionsHost = 'sessions.hytale.com' }
            if (-not $BaseUrlWasSet) { $BaseUrl = 'https://sessions.hytale.com' }
            $RedirectDomains = @(
                'sessions.SeedOfAnarky.fr',
                'account-data.SeedOfAnarky.fr',
                'api.SeedOfAnarky.fr',
                'cdn.SeedOfAnarky.fr',
                'telemetry.SeedOfAnarky.fr',
                'SeedOfAnarky.fr',
                'sessions.hytale.com',
                'account-data.hytale.com',
                'api.hytale.com',
                'cdn.hytale.com',
                'telemetry.hytale.com',
                'hytale.com'
            )
        }
    }
}

function Remove-SeedOfAnarkyRedirects {
    $content = Get-Content $HostsFile -Raw -ErrorAction SilentlyContinue
    if ($content -match [regex]::Escape($MarkerStart)) {
        Write-Host "[HOSTS] Removing redirects..." -ForegroundColor Yellow
        $pattern = "(?s)$([regex]::Escape($MarkerStart)).*?$([regex]::Escape($MarkerEnd))\r?\n?"
        $newContent = $content -replace $pattern, ''
        $maxAttempts = 40
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                Set-Content -Path $HostsFile -Value $newContent -NoNewline -Encoding ASCII
                $null = ipconfig /flushdns 2>&1
                break
            } catch {
                if ($attempt -ge $maxAttempts) { throw }
                Start-Sleep -Milliseconds 250
            }
        }
        Start-Sleep -Milliseconds 500
        Write-Host "[HOSTS] Redirects removed" -ForegroundColor Green
        return $true
    }
    return $false
}

function Add-SeedOfAnarkyRedirects {
    $content = Get-Content $HostsFile -Raw -ErrorAction SilentlyContinue
    if ($content -match [regex]::Escape($MarkerStart)) {
        # Refresh existing block to ensure domain list is current
        Remove-SeedOfAnarkyRedirects | Out-Null
    }
    
    $block = "`n$MarkerStart`n"
    foreach ($d in $RedirectDomains) {
        $block += "127.0.0.1 $d`n"
        $block += "127.0.0.1 www.$d`n"
    }
    $block += "$MarkerEnd`n"
    
    $maxAttempts = 40
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Add-Content -Path $HostsFile -Value $block -Encoding ASCII
            $null = ipconfig /flushdns 2>&1
            break
        } catch {
            if ($attempt -ge $maxAttempts) { throw }
            Start-Sleep -Milliseconds 250
        }
    }
    Write-Host "[HOSTS] Redirects added" -ForegroundColor Green
}

# ============================================================
# LOGGING
# ============================================================

function Write-Log {
    param([string]$Message, [string]$Color = 'White', [string]$Source = 'SYSTEM')
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "[$timestamp] [$Source] $Message"
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    Write-Host $line -ForegroundColor $Color
}

function Write-Section {
    param([string]$Title, [string]$Source = 'SYSTEM')
    $border = "=" * 70
    Write-Log $border 'Cyan' $Source
    Write-Log $Title 'Cyan' $Source
    Write-Log $border 'Cyan' $Source
}

# ============================================================
# JAVA RUNTIME (java.exe) - REQUIRED FOR SINGLEPLAYER WORLD LOAD
# ============================================================

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

function Get-CommandPathSafe {
    param([Parameter(Mandatory = $true)][string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { return $null }

    if ($cmd.PSObject.Properties.Match('Source').Count -gt 0 -and $cmd.Source) { return [string]$cmd.Source }
    if ($cmd.PSObject.Properties.Match('Path').Count -gt 0 -and $cmd.Path) { return [string]$cmd.Path }
    if ($cmd.PSObject.Properties.Match('Definition').Count -gt 0 -and $cmd.Definition) { return [string]$cmd.Definition }

    return $null
}

function Resolve-JavaExe {
    $p = Get-CommandPathSafe -Name 'java'
    if ($p -and (Test-Path $p)) { return $p }

    if ($env:JAVA_HOME) {
        $p2 = Join-Path $env:JAVA_HOME 'bin\java.exe'
        if (Test-Path $p2) { return $p2 }
    }

    $candidates = @()

    if ($env:ProgramFiles) {
        $candidates += @(Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Java\*\bin\java.exe') -ErrorAction SilentlyContinue)
        $candidates += @(Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Microsoft\jdk*\bin\java.exe') -ErrorAction SilentlyContinue)
        $candidates += @(Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Eclipse Adoptium\*\bin\java.exe') -ErrorAction SilentlyContinue)
        $candidates += @(Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Zulu\*\bin\java.exe') -ErrorAction SilentlyContinue)
    }
    if (${env:ProgramFiles(x86)}) {
        $candidates += @(Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Java\*\bin\java.exe') -ErrorAction SilentlyContinue)
        $candidates += @(Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\jdk*\bin\java.exe') -ErrorAction SilentlyContinue)
        $candidates += @(Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Eclipse Adoptium\*\bin\java.exe') -ErrorAction SilentlyContinue)
        $candidates += @(Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Zulu\*\bin\java.exe') -ErrorAction SilentlyContinue)
    }

    $candidates = @($candidates | Where-Object { $_ -and $_.FullName } | Sort-Object FullName -Descending)
    if ($candidates.Count -gt 0) { return [string]$candidates[0].FullName }

    return $null
}

function Ensure-JavaRuntime {
    Refresh-ProcessPathFromRegistry

    $javaExe = Resolve-JavaExe
    if (-not $javaExe) {
        Write-Log "Java not found (java.exe). Singleplayer worlds require Java to start HytaleServer.jar." 'Yellow' 'SYSTEM'

        $winget = Get-Command winget -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $winget) {
            Write-Log "winget not found. Install Java 21+ (Microsoft OpenJDK / Temurin) and re-run." 'Yellow' 'SYSTEM'
            return $false
        }

        $resp = Read-Host "Install Java automatically now using winget? (Y/N)"
        if ($resp -notmatch '^[Yy]') { return $false }

        Write-Log "Installing Java via winget (Microsoft.OpenJDK.21)..." 'Yellow' 'SYSTEM'
        & winget install -e --id Microsoft.OpenJDK.21 --accept-package-agreements --accept-source-agreements 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Log "winget failed to install Java (exit=$LASTEXITCODE). Install Java manually and re-run." 'Red' 'SYSTEM'
            return $false
        }

        Refresh-ProcessPathFromRegistry
        $javaExe = Resolve-JavaExe
        if (-not $javaExe) {
            Write-Log "Java install completed but java.exe still wasn't detected. Re-run the launcher." 'Red' 'SYSTEM'
            return $false
        }
    }

    $javaBin = Split-Path $javaExe -Parent
    if ($javaBin -and ($env:Path -notlike "*$javaBin*")) {
        $env:Path = "$javaBin;$env:Path"
    }

    $javaHome = Split-Path $javaBin -Parent
    if ($javaHome -and (-not $env:JAVA_HOME)) {
        $env:JAVA_HOME = $javaHome
    }

    Write-Log "Java runtime OK: $javaExe" 'Green' 'SYSTEM'
    return $true
}

# ============================================================
# PROCESS ARG QUOTING (Windows CreateProcess)
# ============================================================

function Escape-WinCmdArg {
    param([AllowNull()][string]$Arg)

    # Windows CreateProcess command line quoting rules:
    # - quote args containing whitespace/quotes (or empty)
    # - escape embedded quotes and backslashes before quotes
    if ($null -eq $Arg -or $Arg.Length -eq 0) { return '""' }
    if ($Arg -notmatch '[\s"]') { return $Arg }

    $bs = [char]92   # \
    $qt = [char]34   # "
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($qt)

    $backslashes = 0
    foreach ($c in $Arg.ToCharArray()) {
        if ($c -eq $bs) {
            $backslashes++
            continue
        }

        if ($c -eq $qt) {
            # 2N+1 backslashes then a literal quote
            [void]$sb.Append($bs, $backslashes * 2 + 1)
            [void]$sb.Append($qt)
            $backslashes = 0
            continue
        }

        if ($backslashes -gt 0) {
            [void]$sb.Append($bs, $backslashes)
            $backslashes = 0
        }

        [void]$sb.Append($c)
    }

    if ($backslashes -gt 0) {
        # Escape trailing backslashes before the closing quote.
        [void]$sb.Append($bs, $backslashes * 2)
    }

    [void]$sb.Append($qt)
    return $sb.ToString()
}

# ============================================================
# JAVA TRUSTSTORE
# ============================================================

function Ensure-EmuTrustStore {
    if (-not (Test-Path $EmuCertPath)) {
        Write-Log "EMU cert not found: $EmuCertPath" 'Yellow' 'SYSTEM'
        return $false
    }

    $keytoolCmd = $null

    # Try PATH first.
    $keytoolInfo = Get-Command keytool -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($keytoolInfo) {
        if ($keytoolInfo.PSObject.Properties.Match('Source').Count -gt 0 -and $keytoolInfo.Source) { $keytoolCmd = $keytoolInfo.Source }
        elseif ($keytoolInfo.PSObject.Properties.Match('Path').Count -gt 0 -and $keytoolInfo.Path) { $keytoolCmd = $keytoolInfo.Path }
        elseif ($keytoolInfo.PSObject.Properties.Match('Definition').Count -gt 0 -and $keytoolInfo.Definition) { $keytoolCmd = $keytoolInfo.Definition }
    }

    # Fall back to JAVA_HOME (common on machines with Java installed but not on PATH).
    if (-not $keytoolCmd -and $env:JAVA_HOME) {
        $p = Join-Path $env:JAVA_HOME 'bin\keytool.exe'
        if (Test-Path $p) { $keytoolCmd = $p }
    }

    # Fall back to locating java.exe then walking up to its bin.
    if (-not $keytoolCmd) {
        $javaInfo = Get-Command java -ErrorAction SilentlyContinue | Select-Object -First 1
        $javaPath = $null
        if ($javaInfo) {
            if ($javaInfo.PSObject.Properties.Match('Source').Count -gt 0 -and $javaInfo.Source) { $javaPath = $javaInfo.Source }
            elseif ($javaInfo.PSObject.Properties.Match('Path').Count -gt 0 -and $javaInfo.Path) { $javaPath = $javaInfo.Path }
            elseif ($javaInfo.PSObject.Properties.Match('Definition').Count -gt 0 -and $javaInfo.Definition) { $javaPath = $javaInfo.Definition }
        }

        if ($javaPath) {
            try {
                $javaHome = Split-Path (Split-Path $javaPath -Parent) -Parent
                $p = Join-Path $javaHome 'bin\keytool.exe'
                if (Test-Path $p) { $keytoolCmd = $p }
            } catch { }
        }
    }

    if (-not $keytoolCmd) {
        Write-Log "keytool not found. Skipping Java truststore step (only needed for Java-based server tools)." 'Yellow' 'SYSTEM'
        return $false
    }

    $needsImport = $true
    if (Test-Path $EmuTrustStore) {
        try {
            & $keytoolCmd -list -keystore $EmuTrustStore -storepass $EmuTrustStorePass -alias $EmuTrustStoreAlias *> $null
            if ($LASTEXITCODE -eq 0) { $needsImport = $false }
        } catch { }
    }

    if ($needsImport) {
        try {
            if (Test-Path $EmuTrustStore) {
                & $keytoolCmd -delete -keystore $EmuTrustStore -storepass $EmuTrustStorePass -alias $EmuTrustStoreAlias *> $null
            }
            # keytool writes informational messages to stderr; avoid treating them as terminating errors.
            $oldEap = $ErrorActionPreference
            $keytoolOutput = $null
            try {
                $ErrorActionPreference = 'Continue'
                $keytoolOutput = & $keytoolCmd -importcert -noprompt `
                    -alias $EmuTrustStoreAlias `
                    -file $EmuCertPath `
                    -keystore $EmuTrustStore `
                    -storepass $EmuTrustStorePass 2>&1
            } finally {
                $ErrorActionPreference = $oldEap
            }
            if ($LASTEXITCODE -ne 0) {
                $outText = ($keytoolOutput | Out-String).Trim()
                throw "keytool failed (exit=$LASTEXITCODE)`n$outText"
            }
            Write-Log "Created/updated Java truststore: $EmuTrustStore" 'Green' 'SYSTEM'
        } catch {
            Write-Log "Failed to create truststore: $($_.Exception.Message)" 'Red' 'SYSTEM'
            return $false
        }
    } else {
        Write-Log "Java truststore already contains EMU cert: $EmuTrustStore" 'Green' 'SYSTEM'
    }

    $javaOpts = "-Djavax.net.ssl.trustStore=`"$EmuTrustStore`" -Djavax.net.ssl.trustStorePassword=$EmuTrustStorePass"
    if ($env:JAVA_TOOL_OPTIONS) {
        $env:JAVA_TOOL_OPTIONS = "$env:JAVA_TOOL_OPTIONS $javaOpts"
    } else {
        $env:JAVA_TOOL_OPTIONS = $javaOpts
    }
    Write-Log "JAVA_TOOL_OPTIONS set for truststore" 'Green' 'SYSTEM'
    return $true
}

# ============================================================
# WINDOWS TRUST (for HytaleClient.exe JWKS fetch)
# ============================================================

function Ensure-EmuCertTrustedForWindowsClient {
    if (-not (Test-Path $EmuCertPath)) {
        Write-Log "EMU cert not found: $EmuCertPath" 'Yellow' 'SYSTEM'
        return $false
    }

    $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($EmuCertPath)
    $thumb = $certObj.Thumbprint

    $storePath = 'Cert:\CurrentUser\Root'
    $already = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
    if ($already) {
        Write-Log "Windows trust already contains EMU TLS cert: $thumb" 'Green' 'SYSTEM'
        return $true
    }

    $certutil = Get-Command certutil.exe -ErrorAction SilentlyContinue
    if (-not $certutil) {
        Write-Log "certutil.exe not found; cannot install EMU TLS cert into Windows trust store" 'Yellow' 'SYSTEM'
        return $false
    }

    $out = & certutil.exe -user -addstore Root $EmuCertPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        $outText = ($out | Out-String).Trim()
        Write-Log "certutil failed to add cert to CurrentUser Root store (exit=$LASTEXITCODE): $outText" 'Red' 'SYSTEM'
        return $false
    }

    Write-Log "Installed EMU TLS cert into Windows CurrentUser Trusted Root store: $thumb" 'Green' 'SYSTEM'
    return $true
}

# ============================================================
# JWT DECODER
# ============================================================

function ConvertFrom-Base64Url {
    param([string]$Text)
    $padded = $Text.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        2 { $padded += '==' }
        3 { $padded += '=' }
    }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($padded))
}

function Decode-Jwt {
    param([string]$Jwt)
    if ([string]::IsNullOrEmpty($Jwt)) { return $null }
    $parts = $Jwt.Split('.')
    if ($parts.Length -lt 2) { return $null }
    try {
        return @{
            Header = (ConvertFrom-Base64Url $parts[0]) | ConvertFrom-Json
            Payload = (ConvertFrom-Base64Url $parts[1]) | ConvertFrom-Json
            Signature = $parts[2]
        }
    } catch { return $null }
}

# ============================================================
# TRACED HTTP REQUEST
# ============================================================

function Invoke-TracedRequest {
    param(
        [string]$Url,
        [string]$Method = 'POST',
        [object]$Body = $null,
        [hashtable]$Headers = @{}
    )

    $requestId = [guid]::NewGuid().ToString('N').Substring(0, 8).ToUpper()
    $bodyJson = if ($Body) { $Body | ConvertTo-Json -Compress -Depth 20 } else { $null }
    
    $Headers['User-Agent'] = 'HytaleLauncher/1.0'
    if ($bodyJson) { $Headers['Content-Type'] = 'application/json' }

    Write-Section "LAUNCHER REQUEST [$requestId] - $Method $Url" 'LAUNCHER'
    
    $modeLabel = if ($script:ActiveMode -eq 1) { "REAL SERVER" } else { "LOCAL EMU SERVER" }
    Write-Log "Source: PowerShell Launcher" 'Yellow' 'LAUNCHER'
    Write-Log "Target: $modeLabel" 'Yellow' 'LAUNCHER'
    Write-Log "" 'White' 'LAUNCHER'
    Write-Log "URL: $Url" 'White' 'LAUNCHER'
    Write-Log "Method: $Method" 'White' 'LAUNCHER'
    
    if ($bodyJson) {
        Write-Log "Body: $bodyJson" 'White' 'LAUNCHER'
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = $null
    $raw = $null
    $parsed = $null

    try {
        $params = @{
            Method = $Method
            Uri = $Url
            Headers = $Headers
            UseBasicParsing = $true
            TimeoutSec = 30
        }
        if ($bodyJson) {
            $params['Body'] = $bodyJson
            $params['ContentType'] = 'application/json'
        }
        
        $resp = Invoke-WebRequest @params
        $status = [int]$resp.StatusCode
        $raw = $resp.Content
    } catch {
        Write-Log "ERROR: $($_.Exception.Message)" 'Red' 'LAUNCHER'
        $webResp = $_.Exception.Response
        if ($webResp) {
            try { $status = [int]$webResp.StatusCode } catch { }
            try {
                $stream = $webResp.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $raw = $reader.ReadToEnd()
                $reader.Close()
            } catch { }
        }
    }

    $sw.Stop()
    
    Write-Log "" 'White' 'LAUNCHER'
    Write-Log "Response Status: $status" 'Green' 'LAUNCHER'
    Write-Log "Response Time: $($sw.ElapsedMilliseconds)ms" 'White' 'LAUNCHER'
    
    if ($raw) {
        Write-Log "Response Body:" 'White' 'LAUNCHER'
        Write-Log $raw 'Gray' 'LAUNCHER'
        try { $parsed = $raw | ConvertFrom-Json } catch { }
    }

    Write-Section "END LAUNCHER REQUEST [$requestId]" 'LAUNCHER'

    return [pscustomobject]@{
        StatusCode = $status
        Raw = $raw
        Json = $parsed
    }
}

# ============================================================
# NETWORK MONITOR
# ============================================================

$script:NetworkLog = [System.Collections.ArrayList]::new()
$script:SeenConnections = @{}

function Start-NetworkMonitor {
    param([int]$ProcessId, [string]$ProcessName)
    
    Write-Log "Starting network monitor for $ProcessName (PID: $ProcessId)" 'Magenta' 'NETMON'
    Write-Log "This tracks connections made by the GAME CLIENT (not the launcher)" 'Yellow' 'NETMON'
    
    $job = Start-Job -ScriptBlock {
        param($pid, $logPath, $processName)
        
        $seen = @{}
        
        while ($true) {
            try {
                $netstat = netstat -ano 2>$null | Where-Object { $_ -match "\s$pid\s*$" }
                
                foreach ($line in $netstat) {
                    if ($line -match '^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\w+)?\s+\d+') {
                        $proto = $Matches[1]
                        $local = $Matches[2]
                        $remote = $Matches[3]
                        $state = if ($Matches[4]) { $Matches[4] } else { 'N/A' }
                        
                        if ($remote -eq '*:*' -or $remote -eq '0.0.0.0:0') { continue }
                        
                        $key = "$proto|$remote|$state"
                        if (-not $seen.ContainsKey($key)) {
                            $seen[$key] = $true
                            
                            $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                            
                            $ip = ($remote -split ':')[0]
                            $port = ($remote -split ':')[1]
                            $hostname = $ip
                            try {
                                if ($ip -ne '127.0.0.1' -and $ip -ne '0.0.0.0') {
                                    $dns = [System.Net.Dns]::GetHostEntry($ip)
                                    if ($dns.HostName) { $hostname = $dns.HostName }
                                }
                            } catch { }
                            
                            $entry = "[$timestamp] [CLIENT-NET] $processName -> $hostname`:$port ($ip`:$port) [$state]"
                            Add-Content -LiteralPath $logPath -Value $entry -Encoding UTF8
                            
                            $purpose = switch -Regex ($port) {
                                '^443$' { 'HTTPS - Likely API/Auth call' }
                                '^80$' { 'HTTP - Likely API call' }
                                '^53$' { 'DNS lookup' }
                                default { 'Unknown purpose' }
                            }
                            $entry2 = "[$timestamp] [CLIENT-NET]   ^ Purpose: $purpose"
                            Add-Content -LiteralPath $logPath -Value $entry2 -Encoding UTF8
                        }
                    }
                }
            } catch { }
            
            Start-Sleep -Milliseconds 100
        }
    } -ArgumentList $ProcessId, $LogPath, $ProcessName
    
    return $job
}

# ============================================================
# MODE SELECTION
# ============================================================

Clear-Host
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SeedOfAnarky EMULATOR LAUNCHER - Dual Mode" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($Mode -eq 0) {
    Write-Host "  Select Mode:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [1] PASSTHROUGH - Login to REAL server, trace traffic" -ForegroundColor White
    Write-Host "        (Original behavior: authenticates with sessions.SeedOfAnarky.fr)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    [2] EMULATION  - Login to LOCAL emu server, no internet needed" -ForegroundColor White
    Write-Host "        (Full offline: Python emu handles auth, tokens, entitlements)" -ForegroundColor Gray
    Write-Host ""
    
    do {
        $modeInput = Read-Host "  Enter mode (1 or 2)"
    } while ($modeInput -ne '1' -and $modeInput -ne '2')
    
    $Mode = [int]$modeInput
}

$script:ActiveMode = $Mode

Write-Host ""
if ($Mode -eq 1) {
    Write-Host "  MODE 1: PASSTHROUGH (Real Server)" -ForegroundColor Green
} else {
    Write-Host "  MODE 2: EMULATION (Local Server)" -ForegroundColor Green
}
Write-Host ""

# Check paths
if (-not (Test-Path $ClientExe)) {
    Write-Host "[ERROR] HytaleClient.exe not found at: $ClientExe" -ForegroundColor Red
    Read-Host "Press Enter"
    exit 1
}

# Clear old log
if (Test-Path $LogPath) { Remove-Item $LogPath -Force }

Write-Section "SeedOfAnarky EMU LAUNCHER - MODE $Mode - SESSION START" 'SYSTEM'
Write-Log "Log file: $LogPath" 'White' 'SYSTEM'
Write-Log "Client: $ClientExe" 'White' 'SYSTEM'
Write-Log "Mode: $Mode" 'White' 'SYSTEM'
Write-Log "" 'White' 'SYSTEM'

$javaOk = $true
Write-Section "STEP 0.55: CHECK JAVA RUNTIME (java.exe)" 'SYSTEM'
$javaOk = Ensure-JavaRuntime
if (-not $javaOk) {
    Write-Host ""
    Write-Host "[ERROR] Java is required to load a singleplayer world (HytaleServer.jar)." -ForegroundColor Red
    Write-Host "        Install Java 21+ (or accept the winget prompt), then re-run this launcher." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

$identityToken = $null
$sessionToken = $null
$uuid = $null
$didAddRedirects = $false
$hadRedirects = $false

try {
    if ($Mode -eq 1) {
        # ============================================================
        # MODE 1: PASSTHROUGH - Original behavior
        # ============================================================
        
        # Remove hosts redirects to reach real server
        $hadRedirects = Remove-SeedOfAnarkyRedirects

        # Get credentials
        Write-Host ""
        if (-not $Username) { $Username = Read-Host 'Username' }
        if (-not $Password) {
            $sec = Read-Host 'Password' -AsSecureString
            $Password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
        }
        Write-Log "Credentials: $Username / ****" 'White' 'SYSTEM'

        # STEP 1: Login to real server
        Write-Section "STEP 1: LAUNCHER authenticates with REAL SERVER" 'LAUNCHER'
        
        $login = Invoke-TracedRequest -Url "$BaseUrl/auth/login" -Method 'POST' -Body @{
            username = $Username
            password = $Password
        }
        
        if ($login.Json -and $login.Json.data) {
            $identityToken = [string]$login.Json.data.token
            if ($login.Json.data.user) { $uuid = [string]$login.Json.data.user.uuid }
        }
        if (-not $identityToken) { throw "Login failed - no token" }
        
        Write-Log "SUCCESS: Got identity token from real server" 'Green' 'LAUNCHER'
        Write-Log "UUID: $uuid" 'Green' 'LAUNCHER'

        # Decode token
        $decoded = Decode-Jwt $identityToken
        if ($decoded) {
            Write-Log "TOKEN DETAILS:" 'Cyan' 'LAUNCHER'
            Write-Log "  Algorithm: $($decoded.Header.alg)" 'White' 'LAUNCHER'
            Write-Log "  Key ID: $($decoded.Header.kid)" 'White' 'LAUNCHER'
            Write-Log "  Issuer: $($decoded.Payload.iss)" 'White' 'LAUNCHER'
            Write-Log "  Subject: $($decoded.Payload.sub)" 'White' 'LAUNCHER'
            Write-Log "  Scope: $($decoded.Payload.scope)" 'White' 'LAUNCHER'
        }

        # STEP 2: Get session token from real server
        Write-Section "STEP 2: LAUNCHER gets session token from REAL SERVER" 'LAUNCHER'
        
        $session = Invoke-TracedRequest -Url "$BaseUrl/game-session/child" -Method 'POST' -Body @{
            scope = $Scope
        } -Headers @{ Authorization = "Bearer $identityToken" }
        
        if ($session.Json -and $session.Json.sessionToken) {
            $sessionToken = [string]$session.Json.sessionToken
        }
        # NOTE: session response also contains an identityToken but it has scope "hytale:server"
        # We keep the ORIGINAL identity token from /auth/login which has scope "hytale:client"
        # because that's what HytaleClient.exe checks at launch
        
        Write-Log "SUCCESS: Got session token from real server" 'Green' 'LAUNCHER'

        # STEP 3: Restore redirects (so HytaleClient.exe hits our emu for JWKS)
        Write-Section "STEP 3: RESTORE HOSTS REDIRECTS" 'SYSTEM'
        if ($hadRedirects) { Add-SeedOfAnarkyRedirects }

    } else {
        # ============================================================
        # MODE 2: EMULATION - Talk to local Python server
        # ============================================================
        
        # Ensure hosts redirects are in place
        Write-Section "STEP 0: ENSURE HOSTS REDIRECTS (all traffic -> 127.0.0.1)" 'SYSTEM'
        Add-SeedOfAnarkyRedirects
        $didAddRedirects = $true
        
        # Check if emu server is running
        Write-Section "STEP 0.5: CHECK EMU SERVER" 'SYSTEM'
        try {
            $testResp = Invoke-WebRequest -Uri "$EmuServerUrl/.well-known/jwks.json" `
                -UseBasicParsing -TimeoutSec 5 -Headers @{ Host = $SessionsHost }
            Write-Log "Emu server is running (JWKS returned $($testResp.StatusCode))" 'Green' 'SYSTEM'
        } catch {
            Write-Host "" -ForegroundColor Red
            Write-Host "[ERROR] Emu server is NOT running!" -ForegroundColor Red
            Write-Host "  Start it first: START_EMU.bat" -ForegroundColor Yellow
            Write-Host "" -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit 1
        }

        # Ensure Java trusts EMU cert (server process fetches JWKS over HTTPS)
        Write-Section "STEP 0.6: CONFIGURE JAVA TRUSTSTORE (EMU CERT)" 'SYSTEM'
        Ensure-EmuTrustStore | Out-Null

        # Get credentials (from local users.json)
        Write-Host ""
        Write-Host "  Enter credentials (must match users.json in emu/data/)" -ForegroundColor Yellow
        if (-not $Username) { $Username = Read-Host 'Username' }
        if (-not $Password) {
            $sec = Read-Host 'Password' -AsSecureString
            $Password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
        }
        Write-Log "Credentials: $Username / ****" 'White' 'SYSTEM'

        # STEP 1: Login to emu server
        Write-Section "STEP 1: LAUNCHER authenticates with LOCAL EMU SERVER" 'LAUNCHER'
        Write-Log "Target: $EmuServerUrl (Python emulator)" 'Yellow' 'LAUNCHER'
        
        $login = Invoke-TracedRequest -Url "$EmuServerUrl/auth/login" -Method 'POST' -Body @{
            username = $Username
            password = $Password
        } -Headers @{ Host = $SessionsHost }
        
        if ($login.Json -and $login.Json.data) {
            $identityToken = [string]$login.Json.data.token
            if ($login.Json.data.user) { $uuid = [string]$login.Json.data.user.uuid }
        }
        if (-not $identityToken) { throw "EMU login failed - no token. Check users.json" }
        
        Write-Log "SUCCESS: Got identity token from EMU" 'Green' 'LAUNCHER'
        Write-Log "UUID: $uuid" 'Green' 'LAUNCHER'

        # Decode token
        $decoded = Decode-Jwt $identityToken
        if ($decoded) {
            Write-Log "EMU TOKEN DETAILS:" 'Cyan' 'LAUNCHER'
            Write-Log "  Algorithm: $($decoded.Header.alg)" 'White' 'LAUNCHER'
            Write-Log "  Key ID: $($decoded.Header.kid)" 'White' 'LAUNCHER'
            Write-Log "  Issuer: $($decoded.Payload.iss)" 'White' 'LAUNCHER'
            Write-Log "  Subject: $($decoded.Payload.sub)" 'White' 'LAUNCHER'
        }

        # STEP 2: Get session token from emu server
        Write-Section "STEP 2: LAUNCHER gets session token from LOCAL EMU SERVER" 'LAUNCHER'
        
        $session = Invoke-TracedRequest -Url "$EmuServerUrl/game-session/child" -Method 'POST' -Body @{
            scope = $Scope
        } -Headers @{ 
            Host = $SessionsHost
            Authorization = "Bearer $identityToken" 
        }
        
        if ($session.Json -and $session.Json.sessionToken) {
            $sessionToken = [string]$session.Json.sessionToken
        }
        # NOTE: session response also contains an identityToken but it has scope "hytale:server"
        # We keep the ORIGINAL identity token from /auth/login which has scope "hytale:client"
        # because that's what HytaleClient.exe checks at launch
        if (-not $sessionToken) { throw "EMU session failed - no session token" }
        
        Write-Log "SUCCESS: Got session token from EMU" 'Green' 'LAUNCHER'
    }

    # ============================================================
    # LAUNCH CLIENT (same for both modes)
    # ============================================================
    
    Write-Section "STEP 3.5: ENSURE WINDOWS TRUST (EMU CERT)" 'SYSTEM'
    Ensure-EmuCertTrustedForWindowsClient | Out-Null

    Write-Section "STEP 4: LAUNCHING GAME CLIENT" 'CLIENT'
    Write-Log "Mode: $Mode - Client will connect to $( if ($Mode -eq 1) { 'REDIRECTED (hosts)' } else { 'LOCAL EMU' } ) server" 'Yellow' 'CLIENT'
    Write-Log "All domains resolved to 127.0.0.1 via hosts file" 'Yellow' 'CLIENT'
    Write-Log "" 'White' 'CLIENT'
    
    $clientArgs = @(
        '--app-dir', $AppDir,
        '--user-dir', $UserDir,
        '--auth-mode', 'authenticated',
        '--uuid', $uuid,
        '--name', $Username,
        '--identity-token', $identityToken,
        '--session-token', $sessionToken
    )
    
    Write-Log "Command: HytaleClient.exe" 'White' 'CLIENT'
    Write-Log "  --app-dir $AppDir" 'Gray' 'CLIENT'
    Write-Log "  --user-dir $UserDir" 'Gray' 'CLIENT'
    Write-Log "  --auth-mode authenticated" 'Gray' 'CLIENT'
    Write-Log "  --uuid $uuid" 'Gray' 'CLIENT'
    Write-Log "  --name $Username" 'Gray' 'CLIENT'
    Write-Log "  --identity-token <token>" 'Gray' 'CLIENT'
    Write-Log "  --session-token <token>" 'Gray' 'CLIENT'
    
    if (-not (Test-Path $UserDir)) { New-Item -ItemType Directory -Force -Path $UserDir | Out-Null }
    
    # Start-Process in Windows PowerShell joins string[] without quoting. Build a quoted command line
    # so paths like "C:\\...\\Version 2026.02.06-aa1b071c2" work reliably.
    $clientArgString = ($clientArgs | ForEach-Object { Escape-WinCmdArg $_ }) -join ' '
    # HytaleClient.exe is a console-subsystem app (it prints --help / logs to stdout). On some systems,
    # launching via ShellExecute (Start-Process default) causes it to exit immediately with code 0 and no UI.
    # -NoNewWindow forces CreateProcess + attach to the current console, which reliably starts the actual client.
    $proc = Start-Process -FilePath $ClientExe -ArgumentList $clientArgString -PassThru -WorkingDirectory $ClientDir -NoNewWindow
    
    Write-Log "" 'White' 'CLIENT'
    Write-Log "CLIENT STARTED! PID: $($proc.Id)" 'Green' 'CLIENT'
    
    # Start network monitor
    Write-Section "MONITORING CLIENT NETWORK ACTIVITY" 'NETMON'
    Write-Log "All connections below are made by the GAME CLIENT (HytaleClient.exe)" 'Yellow' 'NETMON'
    if ($Mode -eq 2) {
        Write-Log "Mode 2: Expect ALL SeedOfAnarky connections to go to 127.0.0.1" 'Yellow' 'NETMON'
    }
    Write-Log "" 'White' 'NETMON'
    
    $monitorJob = Start-NetworkMonitor -ProcessId $proc.Id -ProcessName "HytaleClient.exe"
    
    # Wait for client
    Write-Host ""
    Write-Host "Client is running. Use the game normally, then close it." -ForegroundColor Green
    Write-Host "All network activity is being logged..." -ForegroundColor Yellow
    Write-Host ""
    
    while (-not $proc.HasExited) {
        Start-Sleep -Seconds 1
    }
    
    Write-Log "" 'White' 'CLIENT'
    Write-Log "CLIENT EXITED with code: $($proc.ExitCode)" 'Yellow' 'CLIENT'
    
    # Stop monitor
    if ($monitorJob) {
        Stop-Job $monitorJob -ErrorAction SilentlyContinue
        Remove-Job $monitorJob -ErrorAction SilentlyContinue
    }

} catch {
    Write-Log "ERROR: $($_.Exception.Message)" 'Red' 'SYSTEM'
    Write-Log $_.ScriptStackTrace 'Red' 'SYSTEM'
    if ($Mode -eq 1 -and $hadRedirects) { Add-SeedOfAnarkyRedirects }
}

# ============================================================
# CLEANUP HOSTS REDIRECTS
# ============================================================

if ($didAddRedirects) {
    Write-Section "STEP 9: CLEANUP HOSTS REDIRECTS" 'SYSTEM'
    Remove-SeedOfAnarkyRedirects | Out-Null
}

# ============================================================
# SUMMARY
# ============================================================

Write-Section "TRACE COMPLETE - SUMMARY" 'SYSTEM'
Write-Log "" 'White' 'SYSTEM'
Write-Log "Mode: $Mode ($( if ($Mode -eq 1) { 'Passthrough' } else { 'Emulation' } ))" 'Cyan' 'SYSTEM'
Write-Log "" 'White' 'SYSTEM'

if ($Mode -eq 1) {
    Write-Log "What happened (Mode 1 - Passthrough):" 'Cyan' 'SYSTEM'
    Write-Log "  1. [LAUNCHER] Logged into REAL server" 'White' 'SYSTEM'
    Write-Log "  2. [LAUNCHER] Got tokens from REAL server" 'White' 'SYSTEM'
    Write-Log "  3. [SYSTEM] Hosts file redirected domains -> 127.0.0.1" 'White' 'SYSTEM'
    Write-Log "  4. [CLIENT] Game client started with REAL tokens" 'White' 'SYSTEM'
    Write-Log "  5. [CLIENT-NET] Client network connections logged above" 'White' 'SYSTEM'
} else {
    Write-Log "What happened (Mode 2 - Emulation):" 'Cyan' 'SYSTEM'
    Write-Log "  1. [SYSTEM] Hosts file redirected all domains -> 127.0.0.1" 'White' 'SYSTEM'
    Write-Log "  2. [LAUNCHER] Logged into LOCAL EMU server" 'White' 'SYSTEM'
    Write-Log "  3. [LAUNCHER] Got EMU-generated tokens (Ed25519 signed)" 'White' 'SYSTEM'
    Write-Log "  4. [CLIENT] Game client started with EMU tokens" 'White' 'SYSTEM'
    Write-Log "  5. [CLIENT] Client verified JWKS -> got our EMU public key" 'White' 'SYSTEM'
    Write-Log "  6. [CLIENT] Client requested entitlements from EMU" 'White' 'SYSTEM'
    Write-Log "  7. [CLIENT-NET] All traffic stayed local (127.0.0.1)" 'White' 'SYSTEM'
}

Write-Log "" 'White' 'SYSTEM'
Write-Log "Log saved to: $LogPath" 'Green' 'SYSTEM'
Write-Log "Emu server log: emu/logs/emu_trace.log" 'Green' 'SYSTEM'

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  DONE! Check the logs for full request/response trace" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to exit"
