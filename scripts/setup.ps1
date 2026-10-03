param([string]$PythonExecutable = 'python')
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $projectRoot
& $PythonExecutable -c "import sys; assert sys.version_info >= (3, 12), 'Python 3.12 or newer is required'"
if ($LASTEXITCODE -ne 0) { throw 'Use Python 3.12 or newer; Python 3.12 is the validated release runtime.' }
& $PythonExecutable -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed.' }
& '.\.venv\Scripts\python.exe' -m pip install --require-hashes -r requirements.lock.txt
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
Push-Location -LiteralPath (Join-Path $projectRoot 'frontend')
try {
    npm.cmd ci
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
} finally { Pop-Location }
Write-Output 'Setup complete. Run scripts\start-local.ps1 and open the printed http://127.0.0.1:8000/#token=... URL'
