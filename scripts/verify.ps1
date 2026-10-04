param([string]$PythonExecutable = '')
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $projectRoot
if (-not $PythonExecutable) { $PythonExecutable = Join-Path $projectRoot '.venv\Scripts\python.exe' }
$env:PYTHONPATH = Join-Path $projectRoot 'backend'
& $PythonExecutable -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Dependency consistency failed.' }
& $PythonExecutable -m pytest tests -q
if ($LASTEXITCODE -ne 0) { throw 'Security regression suite failed.' }
Push-Location -LiteralPath (Join-Path $projectRoot 'frontend')
try {
    npm.cmd run typecheck
    if ($LASTEXITCODE -ne 0) { throw 'Type check failed.' }
    npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
} finally { Pop-Location }
# Start a real backend so the SSR/API contract smoke runs against a live process, not mocks.
$previousToken = $env:VIBEAUDIT_SESSION_TOKEN
$smokePort = if ($env:VIBEAUDIT_SMOKE_PORT) { [int]$env:VIBEAUDIT_SMOKE_PORT } else { 8002 }
$env:VIBEAUDIT_SESSION_TOKEN = & $PythonExecutable -c "import secrets; print(secrets.token_hex(32))"
$backendOut = Join-Path $env:TEMP 'vibeaudit-verify-backend.out.log'
$backendErr = Join-Path $env:TEMP 'vibeaudit-verify-backend.err.log'
$backend = Start-Process -FilePath $PythonExecutable -ArgumentList '-m','vibe_audit','--port',"$smokePort" -WorkingDirectory $projectRoot -PassThru -WindowStyle Hidden -RedirectStandardOutput $backendOut -RedirectStandardError $backendErr
try {
    $ready = $false
    foreach ($attempt in 1..40) {
        Start-Sleep -Milliseconds 500
        if ($backend.HasExited) { break }
        try {
            $probe = New-Object System.Net.Sockets.TcpClient
            $probe.Connect('127.0.0.1', $smokePort)
            $probe.Close()
            $ready = $true
            break
        } catch { }
    }
    if (-not $ready) {
        Get-Content $backendOut, $backendErr -ErrorAction SilentlyContinue | Write-Output
        throw "Backend did not open port $smokePort for the SSR/API contract smoke."
    }
    node frontend/scripts/contract-smoke.mjs --base-url "http://127.0.0.1:$smokePort"
    if ($LASTEXITCODE -ne 0) { throw 'SSR/API contract smoke failed.' }
} finally {
    if (-not $backend.HasExited) { Stop-Process -Id $backend.Id -Force }
    if ($null -eq $previousToken) { Remove-Item Env:\VIBEAUDIT_SESSION_TOKEN -ErrorAction SilentlyContinue } else { $env:VIBEAUDIT_SESSION_TOKEN = $previousToken }
}
# The committed manifest must hash exactly the sources and the UI build just produced.
& $PythonExecutable scripts/package-release.py --check
if ($LASTEXITCODE -ne 0) { throw 'Source manifest is stale.' }
Write-Output 'Local checks passed. See docs/VALIDATION.md for untested integrations.'
