param([switch]$OpenAdmin)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$serverExe = Join-Path $root 'gemini-web2api.exe'
$configPath = Join-Path $root 'config.json'
$dbPath = Join-Path $root 'gemini.db'
$adminUrl = 'http://127.0.0.1:8084/admin/'

function Test-AdminReady {
    try {
        $response = Invoke-WebRequest -Uri $adminUrl -UseBasicParsing -TimeoutSec 2
        return $response.StatusCode -eq 200
    } catch { return $false }
}

function Find-FirefoxCookies {
    if ($env:GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB) {
        if (-not (Test-Path -LiteralPath $env:GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB)) {
            throw 'The configured Firefox cookies.sqlite file was not found.'
        }
        return $env:GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB
    }
    $firefoxRoot = Join-Path $env:APPDATA 'Mozilla\Firefox'
    $ini = Join-Path $firefoxRoot 'profiles.ini'
    if (-not (Test-Path -LiteralPath $ini)) { return $null }
    $sections = @()
    $section = $null
    foreach ($line in (Get-Content -LiteralPath $ini -Encoding UTF8)) {
        $line = $line.Trim()
        if ($line -match '^\[([^]]+)\]$') {
            $section = @{ Name = $Matches[1] }
            $sections += $section
        } elseif ($null -ne $section -and $line -match '^([^=]+)=(.*)$') {
            $section[$Matches[1]] = $Matches[2]
        }
    }
    $paths = @()
    foreach ($entry in $sections) {
        $path = $null
        if ($entry.Name -like 'Install*' -and $entry.Default) { $path = $entry.Default }
        if ($entry.Name -like 'Profile*' -and $entry.Default -eq '1' -and $entry.Path) { $path = $entry.Path }
        if ($path) {
            if (-not [IO.Path]::IsPathRooted($path)) { $path = Join-Path $firefoxRoot $path }
            $candidate = Join-Path $path 'cookies.sqlite'
            if (Test-Path -LiteralPath $candidate) { $paths += [IO.Path]::GetFullPath($candidate) }
        }
    }
    $unique = @($paths | Select-Object -Unique)
    if ($unique.Count -eq 1) { return $unique[0] }
    if ($unique.Count -gt 1) {
        Write-Host 'Multiple Firefox profiles found. Set GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB to choose one.'
    }
    return $null
}

$existing = Get-NetTCPConnection -State Listen -LocalPort 8084 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existing) {
    $process = Get-Process -Id $existing.OwningProcess -ErrorAction Stop
    if ($process.Path -ne $serverExe) { throw 'Port 8084 is already in use by another process.' }
    if (-not (Test-AdminReady)) { throw 'The server is running but the admin page is unavailable.' }
    Write-Host 'Gemini server is already running.'
    if ($OpenAdmin) { Start-Process -FilePath $adminUrl }
    return
}

if (-not (Test-Path -LiteralPath $serverExe)) { throw 'gemini-web2api.exe was not found next to this launcher.' }
if (-not (Test-Path -LiteralPath $configPath)) { throw 'config.json was not found next to this launcher.' }
$browserCookies = Find-FirefoxCookies
if ($browserCookies) {
    $env:GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB = $browserCookies
    Write-Host 'Firefox profile detected. Import its cookies once through the admin page.'
} else {
    Remove-Item Env:GEMINI_WEBCHANNEL_FIREFOX_COOKIES_DB -ErrorAction SilentlyContinue
    Write-Host 'Firefox profile was not selected. The admin page can still import cookies manually.'
}
$env:GEMINI_EXPERIMENTAL_BROWSER_LOCALE = 'ru'
$env:GEMINI_WEBCHANNEL_EXPERIMENTAL_HTTP3 = '1'
$env:GEMINI_EXPERIMENTAL_LEGACY_FALLBACK = 'images'
$env:GEMINI_ADMIN_SAME_ORIGIN_ONLY = '1'
$process = Start-Process -FilePath $serverExe -WorkingDirectory $root -ArgumentList @('-config', ('"' + $configPath + '"'), '-db', ('"' + $dbPath + '"')) -WindowStyle Hidden -PassThru
$ready = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    if ($process.HasExited) { throw 'Gemini server exited before it was ready.' }
    if (Test-AdminReady) { $ready = $true; break }
    Start-Sleep -Milliseconds 500
}
if (-not $ready) { throw 'Gemini server did not become ready. Check port 8084.' }
Write-Host 'Gemini server is listening on 127.0.0.1:8084.'
if ($OpenAdmin) { Start-Process -FilePath $adminUrl }
