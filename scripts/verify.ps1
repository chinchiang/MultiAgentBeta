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
# The committed manifest must hash exactly the sources and the UI build just produced.
& $PythonExecutable scripts/package-release.py --check
if ($LASTEXITCODE -ne 0) { throw 'Source manifest is stale.' }
Write-Output 'Local checks passed. See docs/VALIDATION.md for untested integrations.'
