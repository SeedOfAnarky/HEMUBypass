param(
    [switch]$SelfTest,
    [switch]$SelfTestCreate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

# ============================================================
# PATHS (supports running from repo root or emu\)
# ============================================================

$ScriptDir = $PSScriptRoot
$RepoRoot = $null
$EmuDir = $null

if (Test-Path -LiteralPath (Join-Path $ScriptDir 'server.py')) {
    # Script is running from emu\.
    $EmuDir = $ScriptDir
    $RepoRoot = Split-Path $EmuDir -Parent
} else {
    # Script is running from the repo root.
    $RepoRoot = $ScriptDir
    $EmuDir = Join-Path $RepoRoot 'emu'
}

if (-not (Test-Path -LiteralPath $EmuDir)) {
    throw "Missing expected folder: $EmuDir"
}

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-ErrorBox {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Title = 'SOA Launcher'
    )
    [void][System.Windows.Forms.MessageBox]::Show(
        $Message,
        $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
}

function Show-InfoBox {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Title = 'SOA Launcher'
    )
    [void][System.Windows.Forms.MessageBox]::Show(
        $Message,
        $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
}

function Show-ConfirmBox {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Title = 'SOA Launcher'
    )

    $res = [System.Windows.Forms.MessageBox]::Show(
        $Message,
        $Title,
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )

    return ($res -eq [System.Windows.Forms.DialogResult]::Yes)
}

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
        $paths += @(Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'Programs\\Python\\Python*\\python.exe') -ErrorAction SilentlyContinue)
    }
    if ($env:ProgramFiles) {
        $paths += @(Get-ChildItem -Path (Join-Path $env:ProgramFiles 'Python*\\python.exe') -ErrorAction SilentlyContinue)
    }
    if (${env:ProgramFiles(x86)}) {
        $paths += @(Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Python*\\python.exe') -ErrorAction SilentlyContinue)
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

function Test-Pip {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PyExe,
        [string[]]$PyArgs = @()
    )

    try {
        $null = & $PyExe @PyArgs -m pip --version 2>$null
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

function Install-PythonWithWinget {
    param(
        [Version]$MinVersion = [Version]'3.8'
    )

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Show-ErrorBox -Message "Python $MinVersion+ is required, but winget was not found. Install Python manually from https://www.python.org/downloads/windows/ and re-run the launcher."
        return $false
    }

    $candidateIds = @(
        'Python.Python.3.13',
        'Python.Python.3.12',
        'Python.Python.3.11',
        'Python.Python.3.10',
        'Python.Python.3.9',
        'Python.Python.3.8'
    )

    foreach ($id in $candidateIds) {
        & winget install -e --id $id --scope user --accept-package-agreements --accept-source-agreements | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
    }

    Show-ErrorBox -Message "Automatic Python install failed. Install Python $MinVersion+ manually from https://www.python.org/downloads/windows/ and re-run the launcher."
    return $false
}

function Ensure-EmulatorPythonDeps {
    $min = [Version]'3.8'
    $cryptoProbe = "from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key"

    Refresh-ProcessPathFromRegistry
    $py = Resolve-PythonInvocation -MinVersion $min

    $needsPython = (-not $py)
    $needsPip = $false
    $needsCryptoStack = $false
    if ($py) {
        $needsPip = -not (Test-Pip -PyExe $py.Exe -PyArgs $py.Args)
        $needsCryptoStack = -not (Test-PythonSnippet -PyExe $py.Exe -PyArgs $py.Args -Code $cryptoProbe)
    }

    if (-not $needsPython -and -not $needsPip -and -not $needsCryptoStack) { return $true }

    $missing = @()
    if ($needsPython) { $missing += "Python $min+" }
    if (-not $needsPython -and $needsPip) { $missing += "pip (Python package installer)" }
    if ($needsCryptoStack) { $missing += "Python packages: cryptography + cffi" }

    $msg = "The emulator requires:`n`n" + ($missing -join "`n") + "`n`nInstall missing dependencies automatically now?"
    if (-not (Show-ConfirmBox -Message $msg)) {
        Show-ErrorBox -Message "Cannot continue without dependencies. Install Python $min+ and ensure 'cryptography' + 'cffi' are installed, then re-run the launcher."
        return $false
    }

    Show-InfoBox -Message "Installing dependencies. This may take a few minutes."

    if ($needsPython) {
        if (-not (Install-PythonWithWinget -MinVersion $min)) { return $false }
        Refresh-ProcessPathFromRegistry
        $py = Resolve-PythonInvocation -MinVersion $min
        if (-not $py) {
            Show-ErrorBox -Message "Python install completed but Python still wasn't detected. Re-run the launcher, or install Python $min+ manually from https://www.python.org/downloads/windows/."
            return $false
        }
    }

    if (-not (Ensure-Pip -PyExe $py.Exe -PyArgs $py.Args)) {
        Show-ErrorBox -Message "pip could not be enabled for: $($py.Display). Reinstall Python (include pip) and re-run the launcher."
        return $false
    }

    if ($needsCryptoStack) {
        & $py.Exe @($py.Args) -m pip install --user --upgrade cffi cryptography | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Show-ErrorBox -Message "Failed to install Python crypto dependencies. Try running:`n`n$($py.Display) -m pip install cffi cryptography"
            return $false
        }
    }

    if (-not (Test-PythonSnippet -PyExe $py.Exe -PyArgs $py.Args -Code $cryptoProbe)) {
        & $py.Exe @($py.Args) -m pip install --user --upgrade --force-reinstall cffi cryptography | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Show-ErrorBox -Message "Crypto packages are installed but still not working. Try running:`n`n$($py.Display) -m pip install --upgrade --force-reinstall cffi cryptography"
            return $false
        }
    }

    if (-not (Test-PythonSnippet -PyExe $py.Exe -PyArgs $py.Args -Code $cryptoProbe)) {
        Show-ErrorBox -Message "Python crypto dependencies are still broken. Reinstall Python (with pip), then re-run the launcher."
        return $false
    }

    return $true
}

if (-not $SelfTest -and -not $SelfTestCreate) {
    if (-not (Test-IsAdmin)) {
        try {
            $scriptPath = $MyInvocation.MyCommand.Path
            $argList = @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-STA',
                '-WindowStyle', 'Hidden',
                '-File', ('"' + $scriptPath + '"')
            ) -join ' '

            Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -WorkingDirectory $RepoRoot | Out-Null
        } catch {
            Show-ErrorBox -Title 'SOA Launcher' -Message 'Administrator rights are required (UAC prompt was canceled).'
        }
        exit 0
    }
}

function Get-UsersJsonPath {
    Join-Path $EmuDir 'data\users.json'
}

function Read-UsersDb {
    $path = Get-UsersJsonPath
    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{
            users    = @()
            _comment = 'Entitlements: game.base, game.deluxe, game.founder. Skin items must match values in cosmetics.json.'
        }
    }

    $raw = Get-Content -LiteralPath $path -Raw
    # Tolerate UTF-8 BOM if present.
    $raw = $raw -replace '^\uFEFF', ''
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [pscustomobject]@{
            users = @()
        }
    }

    try {
        $cfj = Get-Command ConvertFrom-Json -ErrorAction Stop
        if ($cfj.Parameters.ContainsKey('Depth')) {
            $db = $raw | ConvertFrom-Json -Depth 64
        } else {
            $db = $raw | ConvertFrom-Json
        }
    } catch {
        throw "Failed to parse users.json. File: $path`n$($_.Exception.Message)"
    }

    if (-not ($db | Get-Member -Name users -MemberType NoteProperty)) {
        $db | Add-Member -NotePropertyName users -NotePropertyValue @()
    }
    if ($null -eq $db.users) { $db.users = @() }
    if ($db.users -isnot [System.Array]) { $db.users = @($db.users) }

    return $db
}

function Write-UsersDb {
    param(
        [Parameter(Mandatory = $true)]
        $UsersDb
    )

    $path = Get-UsersJsonPath
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }

    $json = $UsersDb | ConvertTo-Json -Depth 64
    if (-not $json.EndsWith("`n")) { $json += "`n" }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $json, $utf8NoBom)
}

function Get-AccountNames {
    $db = Read-UsersDb
    @($db.users | ForEach-Object { $_.username } | Where-Object { $_ })
}

if ($SelfTest) {
    try {
        $db = Read-UsersDb
        $names = @($db.users | ForEach-Object { $_.username } | Where-Object { $_ })
        Write-Host ("SelfTest OK. Accounts: " + ($names -join ', '))
        exit 0
    } catch {
        Write-Error $_
        exit 1
    }
}

function Show-CreateAccountDialog {
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.IWin32Window]$Owner
    )

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Create Account'
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.ClientSize = New-Object System.Drawing.Size(360, 150)

    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.AutoSize = $true
    $lblUser.Text = 'Username'
    $lblUser.Location = New-Object System.Drawing.Point(12, 15)

    $txtUser = New-Object System.Windows.Forms.TextBox
    $txtUser.Width = 320
    $txtUser.Location = New-Object System.Drawing.Point(12, 35)

    $lblDisplay = New-Object System.Windows.Forms.Label
    $lblDisplay.AutoSize = $true
    $lblDisplay.Text = 'Display Name (optional)'
    $lblDisplay.Location = New-Object System.Drawing.Point(12, 65)

    $txtDisplay = New-Object System.Windows.Forms.TextBox
    $txtDisplay.Width = 320
    $txtDisplay.Location = New-Object System.Drawing.Point(12, 85)

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = 'Create'
    $btnOk.Width = 90
    $btnOk.Location = New-Object System.Drawing.Point(242, 115)
    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Width = 90
    $btnCancel.Location = New-Object System.Drawing.Point(146, 115)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $dlg.AcceptButton = $btnOk
    $dlg.CancelButton = $btnCancel

    [void]$dlg.Controls.AddRange(@($lblUser, $txtUser, $lblDisplay, $txtDisplay, $btnOk, $btnCancel))

    $result = $dlg.ShowDialog($Owner)
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        return $null
    }

    $username = $txtUser.Text
    if ($null -eq $username) { $username = '' }
    $username = $username.Trim()

    $display = $txtDisplay.Text
    if ($null -eq $display) { $display = '' }
    $display = $display.Trim()

    if ([string]::IsNullOrWhiteSpace($username)) {
        Show-ErrorBox -Title 'Create Account' -Message 'Username is required.'
        return $null
    }

    return [pscustomobject]@{
        Username    = $username
        DisplayName = $display
    }
}

function New-SoaAccount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [string]$DisplayName
    )

    $db = Read-UsersDb

    $exists = @($db.users | Where-Object { $_.username -and ($_.username.ToString().ToLowerInvariant() -eq $Username.ToLowerInvariant()) })
    if ($exists.Count -gt 0) {
        throw "Username already exists: $Username"
    }

    $template = $db.users | Select-Object -First 1
    $entitlements = @('game.base', 'game.deluxe', 'game.founder')
    $skin = [pscustomobject]@{}
    $roles = @('player')

    if ($template) {
        if ($template.entitlements) { $entitlements = @($template.entitlements) }
        if ($template.skin) { $skin = $template.skin }
        if ($template.roles) { $roles = @($template.roles) }
    }

    $createdUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $displayNameFinal = $DisplayName
    if ([string]::IsNullOrWhiteSpace($displayNameFinal)) { $displayNameFinal = $Username }

    $newUser = [pscustomobject]@{
        username      = $Username
        password      = '123456'
        uuid          = ([guid]::NewGuid().ToString())
        display_name  = $displayNameFinal
        entitlements  = $entitlements
        skin          = $skin
        roles         = $roles
        created       = $createdUtc
    }

    $db.users = @($db.users) + @($newUser)
    Write-UsersDb -UsersDb $db
}

function Start-Bat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BatName
    )

    $path = Join-Path $RepoRoot $BatName
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing file: $path"
    }
    # Force .bat execution via cmd.exe so it doesn't depend on file associations.
    $cmdArgs = '/c ""' + $path + '""'
    Start-Process -FilePath 'cmd.exe' -ArgumentList $cmdArgs -WorkingDirectory $RepoRoot | Out-Null
}

function Resolve-BatName {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Candidates,
        [Parameter(Mandatory = $true)]
        [string]$Purpose
    )

    foreach ($c in $Candidates) {
        if (-not $c) { continue }
        $p = Join-Path $RepoRoot $c
        if (Test-Path -LiteralPath $p) { return $c }
    }

    throw ("Missing {0} launcher. Tried: {1}" -f $Purpose, ($Candidates -join ', '))
}

function Test-TcpPortOpen {
    param(
        [string]$TargetHost = '127.0.0.1',
        [int]$Port = 443,
        [int]$TimeoutMs = 250
    )

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($ar) | Out-Null
        return $true
    } catch {
        return $false
    } finally {
        try { if ($client) { $client.Close() } } catch { }
    }
}

function Ensure-EmuStarted {
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Label]$StatusLabel,
        [int]$TimeoutSec = 10
    )

    # Avoid HTTPS readiness checks here (Invoke-WebRequest can hang on TLS handshake on some systems).
    # For the GUI flow it's enough to ensure the emulator is started; client/server scripts will do deeper checks.
    if (Test-TcpPortOpen -Port 443 -TimeoutMs 250) {
        $StatusLabel.Text = 'Emulator detected.'
        return $true
    }

    $portOpen = $false
    if (-not $portOpen) {
        $StatusLabel.Text = 'Emulator not running. Starting emulator...'
        [System.Windows.Forms.Application]::DoEvents()
        $emuBat = Resolve-BatName -Purpose 'emulator' -Candidates @(
            'emu\START_EMU.bat',
            'emu\START_SOA_EMULATOR.bat',
            'START_SOA_EMULATOR.bat'
        )
        Start-Bat -BatName $emuBat
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-TcpPortOpen -Port 443 -TimeoutMs 250) {
            $StatusLabel.Text = 'Emulator started.'
            return $true
        }
        $remaining = [int][Math]::Max(0, ($deadline - (Get-Date)).TotalSeconds)
        $StatusLabel.Text = ('Waiting for emulator to open port 443... ({0}s)' -f $remaining)
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 750
    }

    $StatusLabel.Text = 'Emulator not detected yet. Continuing (launch may fail)...'
    return $false
}

function Start-ClientWithAccount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    $launcher = Join-Path $EmuDir 'launcher.ps1'
    if (-not (Test-Path -LiteralPath $launcher)) {
        throw "Missing file: $launcher"
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $args = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"' + $launcher + '"'),
        '-Mode', '2',
        '-Username', ('"' + $Username + '"'),
        '-Password', '"123456"'
    ) -join ' '

    # Run PowerShell launcher inside a cmd.exe window so it shows as cmd (and not PS) for users.
    # Use /k so the window stays open even if PowerShell errors early.
    $cmdArgs = '/k powershell.exe ' + $args

    if ($isAdmin) {
        Start-Process -FilePath 'cmd.exe' -ArgumentList $cmdArgs -WorkingDirectory $RepoRoot | Out-Null
    } else {
        Start-Process -FilePath 'cmd.exe' -Verb RunAs -ArgumentList $cmdArgs -WorkingDirectory $RepoRoot | Out-Null
    }
}

function Remove-SoaAccount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    $db = Read-UsersDb
    $before = @($db.users).Count

    $db.users = @(
        $db.users |
        Where-Object {
            $_.username -and ($_.username.ToString().ToLowerInvariant() -ne $Username.ToLowerInvariant())
        }
    )

    $after = @($db.users).Count
    if ($after -ge $before) {
        throw "Account not found: $Username"
    }

    Write-UsersDb -UsersDb $db
}

function Get-LanIPv4 {
    try {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -and
                $_.IPAddress -ne '127.0.0.1' -and
                $_.IPAddress -ne '0.0.0.0' -and
                $_.IPAddress -notlike '169.254.*'
            } |
            Sort-Object -Property InterfaceIndex
        if ($ips -and $ips.Count -gt 0) { return [string]$ips[0].IPAddress }
    } catch { }

    try {
        $wmi = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction Stop
        foreach ($nic in $wmi) {
            foreach ($ip in @($nic.IPAddress)) {
                if (-not $ip) { continue }
                if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$' -and $ip -ne '127.0.0.1' -and $ip -notlike '169.254.*') {
                    return [string]$ip
                }
            }
        }
    } catch { }

    return $null
}

function Get-ExternalIPv4 {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    try {
        # ipify returns plain text for this endpoint.
        $ip = Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 3
        if ($ip -and ($ip -match '^\d{1,3}(\.\d{1,3}){3}$')) { return [string]$ip }
    } catch { }
    return $null
}

if ($SelfTestCreate) {
    $path = Get-UsersJsonPath
    $hadFile = Test-Path -LiteralPath $path
    $origBytes = $null
    if ($hadFile) {
        $origBytes = [System.IO.File]::ReadAllBytes($path)
    }

    try {
        $name = 'soa_test_' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
        New-SoaAccount -Username $name -DisplayName $name

        $db2 = Read-UsersDb
        $found = @($db2.users | Where-Object { $_.username -eq $name })
        if ($found.Count -ne 1) { throw "SelfTestCreate failed: new account not found after write." }

        Write-Host ("SelfTestCreate OK. Created account: " + $name)
        exit 0
    } catch {
        Write-Error $_
        exit 1
    } finally {
        if ($hadFile) {
            [System.IO.File]::WriteAllBytes($path, $origBytes)
        }
    }
}

if (-not $SelfTest -and -not $SelfTestCreate) {
    if (-not (Ensure-EmulatorPythonDeps)) {
        exit 1
    }
}

try {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'SOA Hytale Emulator'
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $true
    $form.ClientSize = New-Object System.Drawing.Size(520, 290)

    $title = New-Object System.Windows.Forms.Label
    $title.AutoSize = $true
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $title.Text = 'SeedOfAnarky Launcher'
    $title.Location = New-Object System.Drawing.Point(14, 14)

    $lblAccount = New-Object System.Windows.Forms.Label
    $lblAccount.AutoSize = $true
    $lblAccount.Text = 'Account'
    $lblAccount.Location = New-Object System.Drawing.Point(16, 55)

    $cmbAccounts = New-Object System.Windows.Forms.ComboBox
    $cmbAccounts.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $cmbAccounts.Width = 320
    $cmbAccounts.Location = New-Object System.Drawing.Point(16, 75)

    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Text = 'Refresh'
    $btnRefresh.Width = 70
    $btnRefresh.Location = New-Object System.Drawing.Point(350, 73)

    $btnDelete = New-Object System.Windows.Forms.Button
    $btnDelete.Text = 'Delete'
    $btnDelete.Width = 70
    $btnDelete.Location = New-Object System.Drawing.Point(430, 73)

    $btnCreate = New-Object System.Windows.Forms.Button
    $btnCreate.Text = 'Create Account'
    $btnCreate.Width = 120
    $btnCreate.Location = New-Object System.Drawing.Point(16, 110)

    $btnLaunchClient = New-Object System.Windows.Forms.Button
    $btnLaunchClient.Text = 'Login + Launch Client'
    $btnLaunchClient.Width = 180
    $btnLaunchClient.Location = New-Object System.Drawing.Point(156, 110)

    $btnStartEmu = New-Object System.Windows.Forms.Button
    $btnStartEmu.Text = 'Start Emulator'
    $btnStartEmu.Width = 120
    $btnStartEmu.Location = New-Object System.Drawing.Point(350, 110)

    $btnDedicated = New-Object System.Windows.Forms.Button
    $btnDedicated.Text = 'Launch Dedicated Server'
    $btnDedicated.Width = 200
    $btnDedicated.Location = New-Object System.Drawing.Point(16, 155)

    $lblDedicatedHint = New-Object System.Windows.Forms.Label
    $lblDedicatedHint.AutoSize = $true
    $lblDedicatedHint.Text = 'Use /auth to authorize server.'
    $lblDedicatedHint.ForeColor = [System.Drawing.Color]::Red
    $lblDedicatedHint.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $lblDedicatedHint.Location = New-Object System.Drawing.Point(16, 183)

    $grpConnect = New-Object System.Windows.Forms.GroupBox
    $grpConnect.Text = 'Server Connect'
    $grpConnect.Width = 260
    $grpConnect.Height = 80
    $grpConnect.Location = New-Object System.Drawing.Point(240, 145)

    $lnkLocal = New-Object System.Windows.Forms.LinkLabel
    $lnkLocal.AutoSize = $true
    $lnkLocal.Location = New-Object System.Drawing.Point(10, 20)
    $lnkLocal.Text = 'Local:'
    $lnkLocal.Tag = 'localhost'

    $lblLocalVal = New-Object System.Windows.Forms.Label
    $lblLocalVal.AutoSize = $true
    $lblLocalVal.Location = New-Object System.Drawing.Point(70, 20)
    $lblLocalVal.Text = 'localhost'

    $lnkLan = New-Object System.Windows.Forms.LinkLabel
    $lnkLan.AutoSize = $true
    $lnkLan.Location = New-Object System.Drawing.Point(10, 40)
    $lnkLan.Text = 'LAN:'
    $lnkLan.Tag = $null

    $lblLanVal = New-Object System.Windows.Forms.Label
    $lblLanVal.AutoSize = $true
    $lblLanVal.Location = New-Object System.Drawing.Point(70, 40)
    $lblLanVal.Text = '(unknown)'

    $lnkExternal = New-Object System.Windows.Forms.LinkLabel
    $lnkExternal.AutoSize = $true
    $lnkExternal.Location = New-Object System.Drawing.Point(10, 60)
    $lnkExternal.Text = 'External:'
    $lnkExternal.Tag = $null

    $lblExternalVal = New-Object System.Windows.Forms.Label
    $lblExternalVal.AutoSize = $true
    $lblExternalVal.Location = New-Object System.Drawing.Point(70, 60)
    $lblExternalVal.Text = '(unknown)'

    [void]$grpConnect.Controls.AddRange(@(
        $lnkLocal, $lblLocalVal,
        $lnkLan, $lblLanVal,
        $lnkExternal, $lblExternalVal
    ))

    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = 'Exit'
    $btnExit.Width = 80
    $btnExit.Location = New-Object System.Drawing.Point(390, 230)

    $status = New-Object System.Windows.Forms.Label
    $status.AutoSize = $false
    $status.Width = 480
    $status.Height = 40
    $status.Location = New-Object System.Drawing.Point(16, 230)
    $status.Text = 'Password is always 123456 (auto).'

    $refreshAccounts = {
        $cmbAccounts.Items.Clear()
        $names = Get-AccountNames
        foreach ($n in $names) { [void]$cmbAccounts.Items.Add($n) }
        if ($cmbAccounts.Items.Count -gt 0) { $cmbAccounts.SelectedIndex = 0 }
    }

    $btnRefresh.Add_Click({
        try {
            & $refreshAccounts
            $status.Text = 'Accounts refreshed.'
        } catch {
            Show-ErrorBox -Message $_.Exception.Message
        }
    })

    $btnDelete.Add_Click({
        try {
            if ($cmbAccounts.SelectedItem -eq $null) {
                Show-ErrorBox -Title 'Delete Account' -Message 'No account selected.'
                return
            }
            $user = $cmbAccounts.SelectedItem.ToString()

            $confirm = [System.Windows.Forms.MessageBox]::Show(
                ("Delete account '" + $user + "'?"),
                'Delete Account',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

            Remove-SoaAccount -Username $user
            & $refreshAccounts
            $status.Text = "Deleted account: $user"
        } catch {
            Show-ErrorBox -Title 'Delete Account' -Message $_.Exception.Message
        }
    })

    $btnCreate.Add_Click({
        try {
            $info = Show-CreateAccountDialog -Owner $form
            if (-not $info) { return }

            New-SoaAccount -Username $info.Username -DisplayName $info.DisplayName
            & $refreshAccounts

            $idx = $cmbAccounts.Items.IndexOf($info.Username)
            if ($idx -ge 0) { $cmbAccounts.SelectedIndex = $idx }

            $status.Text = "Created account: $($info.Username)"
            Show-InfoBox -Title 'Create Account' -Message ("Created account '" + $info.Username + "' (password is always 123456)." + "`n`nIf the emulator is already running, restart it to pick up the new account.")
        } catch {
            Show-ErrorBox -Title 'Create Account' -Message $_.Exception.Message
        }
    })

    $btnLaunchClient.Add_Click({
        try {
            if ($cmbAccounts.SelectedItem -eq $null) {
                Show-ErrorBox -Title 'Launch Client' -Message 'No account selected. Create an account first.'
                return
            }
            $user = $cmbAccounts.SelectedItem.ToString()
            $status.Text = 'Ensuring emulator is running...'
            [void](Ensure-EmuStarted -StatusLabel $status)
            $status.Text = "Launching client as $user ..."
            Start-ClientWithAccount -Username $user
        } catch {
            Show-ErrorBox -Title 'Launch Client' -Message $_.Exception.Message
        }
    })

    $btnStartEmu.Add_Click({
        try {
            $status.Text = 'Starting emulator...'
            $emuBat = Resolve-BatName -Purpose 'emulator' -Candidates @(
                'emu\START_EMU.bat',
                'emu\START_SOA_EMULATOR.bat',
                'START_SOA_EMULATOR.bat'
            )
            Start-Bat -BatName $emuBat
        } catch {
            Show-ErrorBox -Title 'Start Emulator' -Message $_.Exception.Message
        }
    })

    $copyIp = {
        param($sender, $args)
        try {
            $val = $null
            try { $val = [string]$sender.Tag } catch { }
            if ([string]::IsNullOrWhiteSpace($val)) { return }
            [System.Windows.Forms.Clipboard]::SetText($val)
            $status.Text = "Copied: $val"
        } catch {
            Show-ErrorBox -Title 'Copy' -Message $_.Exception.Message
        }
    }

    $lnkLocal.Add_LinkClicked($copyIp)
    $lnkLan.Add_LinkClicked($copyIp)
    $lnkExternal.Add_LinkClicked($copyIp)

    $btnDedicated.Add_Click({
        try {
            $status.Text = 'Ensuring emulator is running...'
            [void](Ensure-EmuStarted -StatusLabel $status)
            $status.Text = 'Starting dedicated server...'

            $serverBat = Resolve-BatName -Purpose 'dedicated server' -Candidates @(
                'emu\START_SERVER.bat',
                'emu\START_HYTALE_SERVER.bat',
                'emu\START_HYTALE_DEDICATED_SERVER.bat',
                'START_HYTALE_DEDICATED_SERVER.bat',
                'START_SERVER.bat'
            )
            Start-Bat -BatName $serverBat

            # Update connect info after launch
            $lanIp = Get-LanIPv4
            if ($lanIp) {
                $lnkLan.Tag = $lanIp
                $lblLanVal.Text = $lanIp
            } else {
                $lnkLan.Tag = $null
                $lblLanVal.Text = '(unknown)'
            }

            $extIp = Get-ExternalIPv4
            if ($extIp) {
                $lnkExternal.Tag = $extIp
                $lblExternalVal.Text = $extIp
            } else {
                $lnkExternal.Tag = $null
                $lblExternalVal.Text = '(unknown)'
            }
        } catch {
            Show-ErrorBox -Title 'Dedicated Server' -Message $_.Exception.Message
        }
    })

    $btnExit.Add_Click({ $form.Close() })

    [void]$form.Controls.AddRange(@(
        $title,
        $lblAccount, $cmbAccounts, $btnRefresh, $btnDelete,
        $btnCreate, $btnLaunchClient, $btnStartEmu,
        $btnDedicated, $lblDedicatedHint,
        $grpConnect,
        $status, $btnExit
    ))

    & $refreshAccounts

    [void]$form.ShowDialog()
} catch {
    Show-ErrorBox -Message $_.Exception.Message
    exit 1
}
